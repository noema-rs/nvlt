use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use vault_core::{decrypt, encrypt, derive_wrap_key, KdfParams};

use crate::config::{set_private_file_permissions, set_private_dir_permissions, Config};
use crate::device::{compute_device_id, ensure_device_matches, read_stored_device_id};
use crate::error::CliError;
use crate::paths::VaultLayout;
use crate::wipe::wipe_operational_vault;

pub const RATE_SLOT_COUNT: u8 = 15;
const RT_PAYLOAD_VERSION: u8 = 1;
const SLOT_ENC_VERSION: u32 = 1;
const RECOVERY_BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileBind {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub rt_blake3: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RtPayload {
    version: u8,
    slot: u8,
    generation: u32,
    device_id: String,
    key_seed: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WrappedSeed {
    wrap_salt_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SlotEncFile {
    version: u32,
    bind: FileBind,
    primary: WrappedSeed,
    backup: WrappedSeed,
}

#[derive(Serialize, Deserialize)]
pub struct RecoveryPlaintext {
    pub version: u32,
    pub device_id: String,
    pub primary: String,
    pub backup: String,
    pub rate_limit_secret_key_b64: String,
    pub rate_generation: u32,
}

pub fn generate_keypair() -> Result<(SigningKey, String), CliError> {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    let pub_b64 = STANDARD.encode(signing.verifying_key().to_bytes());
    Ok((signing, pub_b64))
}

pub fn verifying_key_from_config(config: &Config) -> Result<VerifyingKey, CliError> {
    let pub_b64 = config
        .vault
        .rate_limit_pub
        .as_deref()
        .ok_or_else(|| CliError::Config("missing rate_limit_pub in config".into()))?;
    let bytes = STANDARD
        .decode(pub_b64)
        .map_err(|_| CliError::Config("invalid rate_limit_pub".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CliError::Config("invalid rate_limit_pub length".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| CliError::Config("invalid rate_limit_pub key".into()))
}

pub fn guard_device(config: &Config) -> Result<(), CliError> {
    if config.vault.device_id.is_none() {
        return Ok(());
    }
    let stored = read_stored_device_id(config)?;
    if ensure_device_matches(stored).is_err() {
        wipe_operational_vault(config)?;
        return Err(CliError::DeviceMismatch);
    }
    Ok(())
}

pub fn ensure_rate_layout(config: &Config, layout: &VaultLayout) -> Result<(), CliError> {
    guard_device(config)?;
    if layout.has_rate_duplas() {
        return Ok(());
    }
    if layout.nvlt_enc.is_file() {
        return Err(CliError::Config(
            "legacy nvlt.enc detected; run `nvlt rate-limit renew` with offline bundle or re-init from snapshot".into(),
        ));
    }
    Err(CliError::RateLimitExhausted)
}

pub fn count_valid_slots(layout: &VaultLayout, config: &Config) -> Result<usize, CliError> {
    let vk = verifying_key_from_config(config)?;
    let generation = config.vault.rate_generation.unwrap_or(0);
    let device_id = read_stored_device_id(config)?;
    let mut n = 0usize;
    for slot in 1..=RATE_SLOT_COUNT {
        if slot_valid(layout, config, slot, &vk, generation, device_id).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

pub(crate) fn slot_valid_for_panic(
    layout: &VaultLayout,
    config: &Config,
    slot: u8,
    vk: &VerifyingKey,
    generation: u32,
    device_id: &str,
) -> Result<(), CliError> {
    slot_valid(layout, config, slot, vk, generation, device_id)
}

fn slot_valid(
    layout: &VaultLayout,
    _config: &Config,
    slot: u8,
    vk: &VerifyingKey,
    generation: u32,
    device_id: &str,
) -> Result<(), CliError> {
    let rt_path = layout.rate_rt_path(slot);
    let enc_path = layout.rate_enc_path(slot);
    if !rt_path.is_file() || !enc_path.is_file() {
        return Err(CliError::Config("missing slot files".into()));
    }
    let payload = verify_rt_file(&rt_path, vk, slot, generation, device_id)?;
    let bind = bind_for_path(&rt_path)?;
    let enc: SlotEncFile = read_slot_enc(&enc_path)?;
    if enc.bind != bind {
        return Err(CliError::Config("enc bind mismatch".into()));
    }
    let _ = payload;
    Ok(())
}

pub fn select_active_slot(layout: &VaultLayout, config: &Config) -> Result<u8, CliError> {
    ensure_rate_layout(config, layout)?;
    let vk = verifying_key_from_config(config)?;
    let generation = config.vault.rate_generation.unwrap_or(0);
    let device_id = read_stored_device_id(config)?.to_string();
    for slot in 1..=RATE_SLOT_COUNT {
        if slot_valid(layout, config, slot, &vk, generation, &device_id).is_ok() {
            return Ok(slot);
        }
    }
    Err(CliError::RateLimitExhausted)
}

pub fn burn_slot(layout: &VaultLayout, slot: u8) -> Result<(), CliError> {
    let rt_path = layout.rate_rt_path(slot);
    if !rt_path.is_file() {
        return Ok(());
    }
    let mut f = fs::OpenOptions::new().append(true).open(&rt_path)?;
    let mut byte = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut byte);
    f.write_all(&byte)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn mint_all_duplas(
    layout: &VaultLayout,
    config: &Config,
    password: &SecretString,
    primary: &SecretString,
    backup: &SecretString,
    signing: &SigningKey,
    generation: u32,
    params: KdfParams,
) -> Result<(), CliError> {
    fs::create_dir_all(&layout.rate_dir)?;
    set_private_dir_permissions(&layout.rate_dir)?;
    let device_id = read_stored_device_id(config)?.to_string();
    for slot in 1..=RATE_SLOT_COUNT {
        write_slot_pair(
            layout,
            password,
            primary,
            backup,
            signing,
            slot,
            generation,
            &device_id,
            params,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_slot_pair(
    layout: &VaultLayout,
    password: &SecretString,
    primary: &SecretString,
    backup: &SecretString,
    signing: &SigningKey,
    slot: u8,
    generation: u32,
    device_id: &str,
    params: KdfParams,
) -> Result<(), CliError> {
    let rt_path = layout.rate_rt_path(slot);
    let enc_path = layout.rate_enc_path(slot);

    let mut key_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_seed);
    let payload = RtPayload {
        version: RT_PAYLOAD_VERSION,
        slot,
        generation,
        device_id: device_id.to_string(),
        key_seed,
    };
    write_rt_file(&rt_path, signing, &payload)?;
    let bind = bind_for_path(&rt_path)?;
    let slot_key = derive_slot_key(password, &payload, &bind)?;
    let primary_wrap = wrap_seed_with_key(&slot_key, primary, params)?;
    let backup_wrap = wrap_seed_with_key(&slot_key, backup, params)?;
    let enc = SlotEncFile {
        version: SLOT_ENC_VERSION,
        bind,
        primary: primary_wrap,
        backup: backup_wrap,
    };
    let json = serde_json::to_vec(&enc)?;
    fs::write(&enc_path, json)?;
    set_private_file_permissions(&enc_path)?;
    Ok(())
}

fn write_rt_file(path: &Path, signing: &SigningKey, payload: &RtPayload) -> Result<(), CliError> {
    let body = serde_json::to_vec(payload)?;
    let sig = signing.sign(&body);
    let mut out = Vec::with_capacity(64 + body.len());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&body);
    fs::write(path, out)?;
    set_private_file_permissions(path)?;
    Ok(())
}

fn verify_rt_file(
    path: &Path,
    vk: &VerifyingKey,
    expected_slot: u8,
    expected_generation: u32,
    expected_device: &str,
) -> Result<RtPayload, CliError> {
    let raw = fs::read(path)?;
    if raw.len() < 64 {
        return Err(CliError::Config("invalid rt file".into()));
    }
    let (sig_bytes, body) = raw.split_at(64);
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CliError::Config("invalid rt sig".into()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify(body, &signature)
        .map_err(|_| CliError::Config("rt signature invalid".into()))?;
    let payload: RtPayload = serde_json::from_slice(body)?;
    if payload.version != RT_PAYLOAD_VERSION
        || payload.slot != expected_slot
        || payload.generation != expected_generation
        || payload.device_id != expected_device
    {
        return Err(CliError::Config("rt payload mismatch".into()));
    }
    Ok(payload)
}

fn bind_for_path(path: &Path) -> Result<FileBind, CliError> {
    let meta = fs::metadata(path)?;
    let raw = fs::read(path)?;
    let hash = Hasher::new().update(&raw).finalize().to_hex().to_string();
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    let (dev, ino) = (meta.dev(), meta.ino());
    #[cfg(not(unix))]
    let (dev, ino) = (0u64, 0u64);
    Ok(FileBind {
        dev,
        ino,
        size: meta.len(),
        rt_blake3: hash,
    })
}

fn read_slot_enc(path: &Path) -> Result<SlotEncFile, CliError> {
    let raw = fs::read(path)?;
    let file: SlotEncFile = serde_json::from_slice(&raw)?;
    if file.version != SLOT_ENC_VERSION {
        return Err(CliError::Config("unsupported slot enc version".into()));
    }
    Ok(file)
}

fn derive_slot_key(
    password: &SecretString,
    payload: &RtPayload,
    bind: &FileBind,
) -> Result<SecretString, CliError> {
    let bind_json = serde_json::to_vec(bind)?;
    let mut ikm = Vec::new();
    ikm.extend_from_slice(password.expose_secret().as_bytes());
    ikm.extend_from_slice(&payload.key_seed);
    ikm.push(payload.slot);
    ikm.extend_from_slice(&payload.generation.to_le_bytes());
    ikm.extend_from_slice(&bind_json);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"nvlt-rate-slot-v1", &mut okm)
        .map_err(|_| CliError::Config("hkdf expand failed".into()))?;
    Ok(SecretString::new(hex::encode(okm)))
}

fn wrap_seed_with_key(
    key: &SecretString,
    seed: &SecretString,
    params: KdfParams,
) -> Result<WrappedSeed, CliError> {
    let mut wrap_salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut wrap_salt);
    let wrap_key = derive_wrap_key(key, &wrap_salt, params)?;
    let ciphertext = encrypt(&wrap_key, seed.expose_secret().as_bytes())?;
    Ok(WrappedSeed {
        wrap_salt_b64: STANDARD.encode(wrap_salt),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
}

fn unwrap_seed_with_key(
    key: &SecretString,
    wrapped: &WrappedSeed,
    params: KdfParams,
) -> Result<SecretString, CliError> {
    let wrap_salt = STANDARD
        .decode(&wrapped.wrap_salt_b64)
        .map_err(|_| CliError::Config("invalid wrap salt".into()))?;
    let ciphertext = STANDARD
        .decode(&wrapped.ciphertext_b64)
        .map_err(|_| CliError::Config("invalid ciphertext".into()))?;
    let wrap_key = derive_wrap_key(key, &wrap_salt, params)?;
    let plain = decrypt(&wrap_key, &ciphertext)?;
    Ok(SecretString::new(
        String::from_utf8(plain).map_err(|_| CliError::Config("invalid seed utf8".into()))?,
    ))
}

pub fn load_primary_from_slot(
    layout: &VaultLayout,
    config: &Config,
    slot: u8,
    password: &SecretString,
    params: KdfParams,
) -> Result<(SecretString, SecretString), CliError> {
    let vk = verifying_key_from_config(config)?;
    let generation = config.vault.rate_generation.unwrap_or(0);
    let device_id = read_stored_device_id(config)?;
    let rt_path = layout.rate_rt_path(slot);
    let payload = verify_rt_file(&rt_path, &vk, slot, generation, device_id)?;
    let bind = bind_for_path(&rt_path)?;
    let enc = read_slot_enc(&layout.rate_enc_path(slot))?;
    if enc.bind != bind {
        return Err(CliError::Config("bind drift".into()));
    }
    let slot_key = derive_slot_key(password, &payload, &bind)?;
    let primary = unwrap_seed_with_key(&slot_key, &enc.primary, params)?;
    let backup = unwrap_seed_with_key(&slot_key, &enc.backup, params)?;
    Ok((primary, backup))
}

pub fn rewrap_slot_after_success(
    layout: &VaultLayout,
    config: &Config,
    slot: u8,
    password: &SecretString,
    primary: &SecretString,
    backup: &SecretString,
    params: KdfParams,
) -> Result<(), CliError> {
    let rt_path = layout.rate_rt_path(slot);
    let enc_path = layout.rate_enc_path(slot);
    let vk = verifying_key_from_config(config)?;
    let generation = config.vault.rate_generation.unwrap_or(0);
    let device_id = read_stored_device_id(config)?;
    let payload = verify_rt_file(&rt_path, &vk, slot, generation, device_id)?;
    let bind = bind_for_path(&rt_path)?;
    let slot_key = derive_slot_key(password, &payload, &bind)?;
    let enc = SlotEncFile {
        version: SLOT_ENC_VERSION,
        bind,
        primary: wrap_seed_with_key(&slot_key, primary, params)?,
        backup: wrap_seed_with_key(&slot_key, backup, params)?,
    };
    fs::write(&enc_path, serde_json::to_vec(&enc)?)?;
    set_private_file_permissions(&enc_path)?;
    Ok(())
}

pub fn write_recovery_bundle(
    bundle_path: &Path,
    recovery_passphrase: &SecretString,
    device_id: &str,
    primary: &SecretString,
    backup: &SecretString,
    signing: &SigningKey,
    generation: u32,
) -> Result<(), CliError> {
    let plain = RecoveryPlaintext {
        version: RECOVERY_BUNDLE_VERSION,
        device_id: device_id.to_string(),
        primary: primary.expose_secret().clone(),
        backup: backup.expose_secret().clone(),
        rate_limit_secret_key_b64: STANDARD.encode(signing.to_bytes()),
        rate_generation: generation,
    };
    let json = serde_json::to_vec(&plain)?;
    let wrap_key = recovery_bundle_key(recovery_passphrase)?;
    let ciphertext = encrypt(&wrap_key, &json)?;
    if let Some(parent) = bundle_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(bundle_path, ciphertext)?;
    set_private_file_permissions(bundle_path)?;
    Ok(())
}

fn recovery_bundle_key(passphrase: &SecretString) -> Result<SecretString, CliError> {
    let params = KdfParams {
        memory_cost_kib: 65536,
        time_cost: 3,
        parallelism: 4,
    };
    let salt = b"nvlt-recovery-bundle";
    derive_wrap_key(passphrase, salt, params).map_err(CliError::from)
}

pub fn read_recovery_bundle(
    bundle_path: &Path,
    recovery_passphrase: &SecretString,
) -> Result<RecoveryPlaintext, CliError> {
    let raw = fs::read(bundle_path)?;
    let wrap_key = recovery_bundle_key(recovery_passphrase)?;
    let json = decrypt(&wrap_key, &raw)?;
    let plain: RecoveryPlaintext = serde_json::from_slice(&json)?;
    if plain.version != RECOVERY_BUNDLE_VERSION {
        return Err(CliError::Config("unsupported recovery bundle version".into()));
    }
    Ok(plain)
}

pub fn setup_local_gate_on_init(
    config: &mut Config,
    layout: &VaultLayout,
    password: &SecretString,
    primary: &SecretString,
    backup: &SecretString,
    signing: &SigningKey,
    params: KdfParams,
) -> Result<(), CliError> {
    let device_id = compute_device_id()?;
    config.vault.device_id = Some(device_id.clone());
    config.vault.rate_limit_pub = Some(STANDARD.encode(signing.verifying_key().as_bytes()));
    config.vault.rate_generation = Some(1);
    if layout.rate_dir.exists() {
        fs::remove_dir_all(&layout.rate_dir)?;
    }
    mint_all_duplas(layout, config, password, primary, backup, signing, 1, params)?;
    Ok(())
}

pub fn remint_with_new_keypair(
    config: &mut Config,
    layout: &VaultLayout,
    password: &SecretString,
    primary: &SecretString,
    backup: &SecretString,
    params: KdfParams,
) -> Result<SigningKey, CliError> {
    let (signing, pub_b64) = generate_keypair()?;
    config.vault.rate_limit_pub = Some(pub_b64);
    let gen = config.vault.rate_generation.unwrap_or(0).saturating_add(1);
    config.vault.rate_generation = Some(gen);
    if layout.rate_dir.exists() {
        fs::remove_dir_all(&layout.rate_dir)?;
    }
    mint_all_duplas(
        layout,
        config,
        password,
        primary,
        backup,
        &signing,
        gen,
        params,
    )?;
    Ok(signing)
}

pub fn renew_duplas(
    config: &mut Config,
    layout: &VaultLayout,
    bundle: &RecoveryPlaintext,
    password: &SecretString,
    primary: &SecretString,
    backup: &SecretString,
    params: KdfParams,
) -> Result<(), CliError> {
    let live = compute_device_id()?;
    if bundle.device_id != live {
        return Err(CliError::Config(
            "recovery bundle device_id does not match this machine".into(),
        ));
    }
    let secret_bytes = STANDARD
        .decode(&bundle.rate_limit_secret_key_b64)
        .map_err(|_| CliError::Config("invalid bundle signing key".into()))?;
    let key_arr: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| CliError::Config("invalid bundle signing key length".into()))?;
    let signing = SigningKey::from_bytes(&key_arr);
    let new_gen = bundle.rate_generation.saturating_add(1);
    config.vault.rate_generation = Some(new_gen);
    config.vault.rate_limit_pub = Some(STANDARD.encode(signing.verifying_key().as_bytes()));
    if layout.rate_dir.exists() {
        fs::remove_dir_all(&layout.rate_dir)?;
    }
    mint_all_duplas(
        layout,
        config,
        password,
        primary,
        backup,
        &signing,
        new_gen,
        params,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::KdfParams;

    #[test]
    fn mint_and_load_slot() {
        let dir = std::env::temp_dir().join(format!("nvlt-rate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let layout = VaultLayout {
            root: dir.clone(),
            config_file: dir.join("config.toml"),
            nvlt_enc: dir.join("nvlt.enc"),
            passwords: dir.join("pass.age"),
            envs_dir: dir.join("envs"),
            files_dir: dir.join("files"),
            totp: dir.join("totp.age"),
            backup: dir.join("backup.age"),
            ssh: dir.join("ssh.age"),
            rate_dir: dir.join("rate"),
        };
        let (signing, pub_b64) = generate_keypair().unwrap();
        let device_id = compute_device_id().unwrap();
        let mut config = Config::default();
        config.vault.device_id = Some(device_id);
        config.vault.rate_limit_pub = Some(pub_b64);
        config.vault.rate_generation = Some(1);
        let password = SecretString::new("pw".into());
        let primary = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
        let backup = SecretString::new("MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK".into());
        let params = KdfParams {
            memory_cost_kib: 256,
            time_cost: 1,
            parallelism: 1,
        };
        mint_all_duplas(
            &layout,
            &config,
            &password,
            &primary,
            &backup,
            &signing,
            1,
            params,
        )
        .unwrap();
        let slot = select_active_slot(&layout, &config).unwrap();
        assert_eq!(slot, 1);
        let (p, _) = load_primary_from_slot(&layout, &config, slot, &password, params).unwrap();
        assert_eq!(p.expose_secret(), primary.expose_secret());
        burn_slot(&layout, slot).unwrap();
        assert!(select_active_slot(&layout, &config).unwrap() == 2);
        let _ = fs::remove_dir_all(&dir);
    }
}
