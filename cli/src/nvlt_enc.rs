use std::fs;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use vault_core::{decrypt, derive_wrap_key, encrypt, KdfParams};

use crate::config::set_private_file_permissions;
use crate::error::CliError;
use crate::paths::VaultLayout;

const NVLT_ENC_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct NvltEncFile {
    version: u32,
    primary: WrappedSeed,
    backup: WrappedSeed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WrappedSeed {
    wrap_salt_b64: String,
    ciphertext_b64: String,
}

fn wrap_seed(
    password: &SecretString,
    seed: &SecretString,
    params: KdfParams,
) -> Result<WrappedSeed, CliError> {
    let mut wrap_salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut wrap_salt);
    let wrap_key = derive_wrap_key(password, &wrap_salt, params)?;
    let ciphertext = encrypt(&wrap_key, seed.expose_secret().as_bytes())?;
    Ok(WrappedSeed {
        wrap_salt_b64: STANDARD.encode(wrap_salt),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
}

fn unwrap_seed(
    password: &SecretString,
    wrapped: &WrappedSeed,
    params: KdfParams,
) -> Result<SecretString, CliError> {
    let wrap_salt = STANDARD
        .decode(&wrapped.wrap_salt_b64)
        .map_err(|_| CliError::Config("invalid nvlt.enc wrap salt".into()))?;
    let ciphertext = STANDARD
        .decode(&wrapped.ciphertext_b64)
        .map_err(|_| CliError::Config("invalid nvlt.enc ciphertext".into()))?;
    let wrap_key = derive_wrap_key(password, &wrap_salt, params)?;
    let plain = decrypt(&wrap_key, &ciphertext)?;
    Ok(SecretString::new(
        String::from_utf8(plain).map_err(|_| CliError::Config("invalid seed utf8".into()))?,
    ))
}

pub fn write_nvlt_enc(
    layout: &VaultLayout,
    password: &SecretString,
    primary: &SecretString,
    backup: &SecretString,
    params: KdfParams,
) -> Result<(), CliError> {
    let file = NvltEncFile {
        version: NVLT_ENC_VERSION,
        primary: wrap_seed(password, primary, params)?,
        backup: wrap_seed(password, backup, params)?,
    };
    let json = serde_json::to_vec(&file)?;
    fs::write(&layout.nvlt_enc, json)?;
    set_private_file_permissions(&layout.nvlt_enc)?;
    Ok(())
}

fn read_file(layout: &VaultLayout) -> Result<NvltEncFile, CliError> {
    if !layout.nvlt_enc.is_file() {
        return Err(CliError::Config(
            "missing nvlt.enc; run `nvlt init --from-snapshot` or `nvlt init`".into(),
        ));
    }
    let raw = fs::read(&layout.nvlt_enc)?;
    let file: NvltEncFile = serde_json::from_slice(&raw)?;
    if file.version != NVLT_ENC_VERSION {
        return Err(CliError::Config("unsupported nvlt.enc version".into()));
    }
    Ok(file)
}

/// Load primary seed without re-writing nvlt.enc (legacy verify paths).
pub fn load_primary_seed_only(
    layout: &VaultLayout,
    password: &SecretString,
    params: KdfParams,
) -> Result<SecretString, CliError> {
    let file = read_file(layout)?;
    unwrap_seed(password, &file.primary, params)
}

/// Load primary seed, re-wrap nvlt.enc on success (legacy vaults).
#[allow(dead_code)]
pub fn load_primary_seed(
    layout: &VaultLayout,
    password: &SecretString,
    params: KdfParams,
) -> Result<SecretString, CliError> {
    let file = read_file(layout)?;
    let primary = unwrap_seed(password, &file.primary, params)?;
    let backup = unwrap_seed(password, &file.backup, params)?;
    write_nvlt_enc(layout, password, &primary, &backup, params)?;
    Ok(primary)
}

/// Load backup seed, re-wrap nvlt.enc on success.
pub fn load_backup_seed(
    layout: &VaultLayout,
    password: &SecretString,
    params: KdfParams,
) -> Result<SecretString, CliError> {
    let file = read_file(layout)?;
    let primary = unwrap_seed(password, &file.primary, params)?;
    let backup = unwrap_seed(password, &file.backup, params)?;
    write_nvlt_enc(layout, password, &primary, &backup, params)?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::KdfParams;

    #[test]
    fn nvlt_enc_round_trip_and_rewrap() {
        let dir = std::env::temp_dir().join(format!("nvlt-enc-{}", std::process::id()));
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
        let password = SecretString::new("pw".into());
        let primary = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
        let backup = SecretString::new("MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK".into());
        let params = KdfParams {
            memory_cost_kib: 256,
            time_cost: 1,
            parallelism: 1,
        };
        write_nvlt_enc(&layout, &password, &primary, &backup, params).unwrap();
        let before = fs::read(&layout.nvlt_enc).unwrap();
        let loaded = load_primary_seed(&layout, &password, params).unwrap();
        assert_eq!(loaded.expose_secret(), primary.expose_secret());
        let after = fs::read(&layout.nvlt_enc).unwrap();
        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&dir);
    }
}
