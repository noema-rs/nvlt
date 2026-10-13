use std::collections::HashMap;
use std::fs;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use vault_core::{decrypt, encrypt, verify_totp};
use vault_envs::EnvVault;
use vault_files::FileVault;
use vault_passwords::{PasswordStore, PasswordsDocument};
use vault_totp::{TotpDocument, TotpStore};

use crate::config::Config;
use crate::confirm::{confirm, confirm_or_cancel};
use crate::error::CliError;
use crate::paths::VaultLayout;
use crate::config::generate_lock_string;
use crate::device::compute_device_id;
use crate::rate_limit::{
    self, generate_keypair, remint_with_new_keypair, setup_local_gate_on_init,
    write_recovery_bundle,
};
use crate::unlock::{prompt_new_password, vault_salt, UnlockSession};
use ed25519_dalek::SigningKey;

const BACKUP_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
struct BackupPayload {
    version: u32,
    data: BackupData,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupData {
    passwords: PasswordsDocument,
    envs: HashMap<String, vault_envs::EnvProfileDocument>,
    files: Vec<BackupFileEntry>,
    totp: TotpDocument,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupFileEntry {
    name: String,
    data_base64: String,
}

pub fn status(config: &Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    println!("Vault root: {}", layout.root.display());
    println!("  lock:      {}", config.vault.lock.as_deref().unwrap_or("(unset)"));
    if layout.has_rate_duplas() {
        let valid = rate_limit::count_valid_slots(&layout, config).unwrap_or(0);
        let gen = config.vault.rate_generation.unwrap_or(0);
        println!("  rate duplas: present (generation {gen}, {valid}/{} valid slots)", rate_limit::RATE_SLOT_COUNT);
    } else {
        println!("  rate duplas: {}", flag(false));
        if layout.nvlt_enc.is_file() {
            println!("  nvlt.enc:  legacy present (migrate via rate-limit renew)");
        }
    }
    println!("  passwords: {}", flag(layout.passwords.is_file()));
    println!("  totp:      {}", flag(layout.totp.is_file()));
    println!("  backup:    {}", flag(layout.backup.is_file()));
    println!("  envs dir:  {}", flag(layout.envs_dir.is_dir()));
    println!("  files dir: {}", flag(layout.files_dir.is_dir()));
    match crate::agent::agent_status() {
        Ok(Some((root, secs))) if root == layout.root.to_string_lossy() => {
            println!("  agent:     unlocked (expires in {secs}s idle)");
        }
        Ok(Some(_)) => println!("  agent:     unlocked (different vault path)"),
        Ok(None) => println!("  agent:     locked"),
        Err(_) => println!("  agent:     unavailable"),
    }
    Ok(())
}

fn flag(ok: bool) -> &'static str {
    if ok {
        "present"
    } else {
        "missing"
    }
}

pub fn init(config: &mut Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    if layout.is_initialized(config) {
        return Err(CliError::AlreadyInitialized {
            vault_root: layout.root.clone(),
        });
    }

    config.vault.lock = Some(generate_lock_string());

    let password = prompt_new_password()?;

    println!("Generating primary TOTP seed...");
    let primary_seed = generate_totp_seed();
    setup_and_verify_authenticator("primary", &primary_seed, &layout)?;

    println!("Generating backup TOTP seed...");
    let backup_seed = generate_totp_seed();
    setup_and_verify_authenticator("backup", &backup_seed, &layout)?;

    println!("Creating vault configuration and encrypted data files...");
    let signing = init_with_secrets(config, &password, &primary_seed, &backup_seed)?;
    crate::config::save_config(config)?;
    prompt_write_recovery_bundle(
        config,
        &primary_seed,
        &backup_seed,
        &signing,
        config.vault.rate_generation.unwrap_or(1),
    )?;
    let _ = crate::agent::lock();

    println!();
    println!("Vault initialized at {}", layout.root.display());
    println!("Primary and backup authenticators verified. Keep both seeds offline.");
    println!("Store the recovery bundle and rate-limit key off this machine.");
    Ok(())
}

pub fn init_from_snapshot(
    snapshot_root: std::path::PathBuf,
    identity: Option<std::path::PathBuf>,
) -> Result<(), CliError> {
    let config = crate::config::load_config()?;
    crate::snapshot::materialize_snapshot(&config, &snapshot_root, identity.as_deref())?;

    let config = crate::config::load_config()?;
    let mut config = config;
    attach_local_rate_duplas(&mut config)?;

    let layout = VaultLayout::from_config(&config);
    println!(
        "Vault ready at {} with local rate duplas.",
        layout.root.display()
    );
    Ok(())
}

fn attach_local_rate_duplas(config: &mut Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    if !layout.passwords.is_file() {
        return Err(CliError::Config(
            "no encrypted vault data found after snapshot extract; check the snapshot bundle".into(),
        ));
    }
    config.lock_str().map_err(|_| {
        CliError::Config(
            "config.toml missing lock after snapshot extract".into(),
        )
    })?;

    if layout.has_rate_duplas() {
        confirm_or_cancel(
            "⚠️  Local rate duplas already exist and will be replaced after successful verification.\n\
                Continue? [y/N]: ",
        )?;
    }

    let password = prompt_new_password_for_unlock()?;
    let primary_seed = prompt_totp_seed("Primary TOTP seed: ")?;
    let backup_seed = prompt_totp_seed("Backup TOTP seed: ")?;
    verify_totp_setup("primary", &primary_seed)?;
    verify_totp_setup("backup", &backup_seed)?;

    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();
    let data_key = vault_core::derive_key(&password, &primary_seed, &salt, params)?;
    if PasswordStore::load_path(&data_key, &layout.passwords).is_err() {
        return Err(CliError::Config(
            "credentials did not decrypt existing vault data".into(),
        ));
    }

    let (signing, _) = generate_keypair()?;
    setup_local_gate_on_init(
        config,
        &layout,
        &password,
        &primary_seed,
        &backup_seed,
        &signing,
        params,
    )?;
    crate::config::save_config(config)?;
    prompt_write_recovery_bundle(
        config,
        &primary_seed,
        &backup_seed,
        &signing,
        config.vault.rate_generation.unwrap_or(1),
    )?;
    if layout.nvlt_enc.is_file() {
        let _ = fs::remove_file(&layout.nvlt_enc);
    }
    println!("Local rate duplas written under {}", layout.rate_dir.display());
    Ok(())
}

pub(crate) fn init_with_secrets(
    config: &mut Config,
    password: &SecretString,
    primary_seed: &SecretString,
    backup_seed: &SecretString,
) -> Result<SigningKey, CliError> {
    let layout = VaultLayout::from_config(config);
    if layout.is_initialized(config) {
        return Err(CliError::AlreadyInitialized {
            vault_root: layout.root.clone(),
        });
    }

    fs::create_dir_all(&layout.root)?;

    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();
    let data_key = vault_core::derive_key(password, primary_seed, &salt, params)?;
    let backup_key = vault_core::derive_key(password, backup_seed, &salt, params)?;

    PasswordStore::empty().save_path(&data_key, &layout.passwords)?;
    TotpStore::empty().save_path(&data_key, &layout.totp)?;
    fs::create_dir_all(&layout.envs_dir)?;
    fs::create_dir_all(&layout.files_dir)?;

    let empty_backup = BackupPayload {
        version: BACKUP_VERSION,
        data: empty_backup_data(),
        created_at: Utc::now(),
    };
    write_backup(&empty_backup, &backup_key, &layout)?;

    let (signing, _) = generate_keypair()?;
    setup_local_gate_on_init(
        config,
        &layout,
        password,
        primary_seed,
        backup_seed,
        &signing,
        params,
    )?;
    Ok(signing)
}

fn prompt_write_recovery_bundle(
    config: &Config,
    primary: &SecretString,
    backup: &SecretString,
    signing: &SigningKey,
    generation: u32,
) -> Result<(), CliError> {
    let computed = compute_device_id()?;
    let device_id = config
        .vault
        .device_id
        .as_deref()
        .unwrap_or(&computed);
    let bundle_path = {
        let p = rpassword::prompt_password("Recovery bundle output path: ").map_err(CliError::Io)?;
        std::path::PathBuf::from(p.trim())
    };
    let pass1 = SecretString::new(
        rpassword::prompt_password("Recovery bundle passphrase: ").map_err(CliError::Io)?,
    );
    let pass2 = SecretString::new(
        rpassword::prompt_password("Confirm recovery bundle passphrase: ").map_err(CliError::Io)?,
    );
    if pass1.expose_secret() != pass2.expose_secret() {
        return Err(CliError::Config("recovery passphrases do not match".into()));
    }
    write_recovery_bundle(
        &bundle_path,
        &pass1,
        device_id,
        primary,
        backup,
        signing,
        generation,
    )?;
    let key_path = bundle_path.with_extension("rate-limit-key");
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    fs::write(&key_path, STANDARD.encode(signing.to_bytes()))?;
    crate::config::set_private_file_permissions(&key_path)?;
    println!("Recovery bundle: {}", bundle_path.display());
    println!("Rate-limit private key (also inside bundle): {}", key_path.display());
    println!("Move both off this machine; they are required for rate-limit renew.");
    Ok(())
}

pub fn backup(config: &Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    confirm_or_cancel(
        "⚠️  You are about to sync backup.age with the current vault state.\n\
            The existing backup.age will be OVERWRITTEN.\n\
         \n\
            Continue? [y/N]: ",
    )?;

    let session = UnlockSession::unlock_interactive(config, &layout)?;
    let backup_key = session.derive_backup_key(config, &layout)?;

    let data = load_backup_data(&layout, &session.data_key)?;
    write_backup(
        &BackupPayload {
            version: BACKUP_VERSION,
            data,
            created_at: Utc::now(),
        },
        &backup_key,
        &layout,
    )?;
    println!("backup.age updated.");
    Ok(())
}

pub fn recover(config: &Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    confirm_or_cancel(
        "⚠️  You are about to recover your vault using the backup TOTP.\n\
            A new primary TOTP will be generated.\n\
            Your current vault files will be REPLACED.\n\
         \n\
            Continue? [y/N]: ",
    )?;

    let password = prompt_new_password_for_unlock()?;
    let backup_seed = if layout.has_rate_duplas() {
        rate_limit::guard_device(config)?;
        let slot = rate_limit::select_active_slot(&layout, config)?;
        let params = config.kdf.to_kdf_params();
        let (_primary, backup) =
            rate_limit::load_primary_from_slot(&layout, config, slot, &password, params)?;
        let _ = rate_limit::burn_slot(&layout, slot);
        backup
    } else if layout.nvlt_enc.is_file() {
        let params = config.kdf.to_kdf_params();
        crate::nvlt_enc::load_backup_seed(&layout, &password, params)?
    } else {
        prompt_totp_seed("Backup TOTP seed: ")?
    };
    let salt = vault_salt(config)?;
    let code = rpassword::prompt_password("Backup TOTP code: ").map_err(CliError::Io)?;
    if !vault_core::verify_totp(&backup_seed, code.trim())? {
        return Err(CliError::UnlockCancelled);
    }
    let backup_key =
        vault_core::derive_key(&password, &backup_seed, &salt, config.kdf.to_kdf_params())?;
    let payload = read_backup(&layout, &backup_key)?;

    let new_primary = generate_totp_seed();
    let params = config.kdf.to_kdf_params();
    let data_key = vault_core::derive_key(&password, &new_primary, &salt, params)?;

    restore_backup_data(&layout, &data_key, payload.data)?;
    reset_ssh_store(&layout, &data_key)?;
    let mut cfg = config.clone();
    let signing = remint_with_new_keypair(
        &mut cfg,
        &layout,
        &password,
        &new_primary,
        &backup_seed,
        params,
    )?;
    crate::config::save_config(&cfg)?;
    prompt_write_recovery_bundle(
        &cfg,
        &new_primary,
        &backup_seed,
        &signing,
        cfg.vault.rate_generation.unwrap_or(1),
    )?;

    let refreshed = load_backup_data(&layout, &data_key)?;
    write_backup(
        &BackupPayload {
            version: BACKUP_VERSION,
            data: refreshed,
            created_at: Utc::now(),
        },
        &backup_key,
        &layout,
    )?;

    println!("Recovery complete. New primary TOTP seed:");
    println!("{}", new_primary.expose_secret());
    Ok(())
}

pub fn rotate(config: &Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    confirm_or_cancel(
        "⚠️  You are about to rotate your credentials.\n\
            This will generate new primary and backup TOTP seeds,\n\
            re-encrypt all vault files, and optionally change your master password.\n\
            The old credentials will no longer work.\n\
         \n\
            Continue? [y/N]: ",
    )?;

    let session = UnlockSession::unlock_interactive(config, &layout)?;
    session.derive_backup_key(config, &layout)?;

    let snapshot = load_backup_data(&layout, &session.data_key)?;

    let new_password = if confirm("Change master password? [y/N]: ")? {
        prompt_new_password()?
    } else {
        session.password.clone()
    };
    let new_primary = generate_totp_seed();
    let new_backup = generate_totp_seed();
    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();

    let data_key = vault_core::derive_key(&new_password, &new_primary, &salt, params)?;
    let backup_key = vault_core::derive_key(&new_password, &new_backup, &salt, params)?;

    restore_backup_data(&layout, &data_key, snapshot)?;
    re_encrypt_ssh_store(&layout, &session.data_key, &data_key)?;
    let mut cfg = config.clone();
    let signing = remint_with_new_keypair(
        &mut cfg,
        &layout,
        &new_password,
        &new_primary,
        &new_backup,
        params,
    )?;
    crate::config::save_config(&cfg)?;
    prompt_write_recovery_bundle(
        &cfg,
        &new_primary,
        &new_backup,
        &signing,
        cfg.vault.rate_generation.unwrap_or(1),
    )?;

    let refreshed = load_backup_data(&layout, &data_key)?;
    write_backup(
        &BackupPayload {
            version: BACKUP_VERSION,
            data: refreshed,
            created_at: Utc::now(),
        },
        &backup_key,
        &layout,
    )?;

    let _ = crate::agent::lock();

    println!("Rotation complete. Save the new seeds:");
    println!("Primary: {}", new_primary.expose_secret());
    println!("Backup:  {}", new_backup.expose_secret());
    println!("Run `nvlt snapshot export` before publishing to git if you use snapshots.");
    Ok(())
}

fn prompt_totp_seed(prompt: &str) -> Result<SecretString, CliError> {
    let seed = rpassword::prompt_password(prompt).map_err(CliError::Io)?;
    Ok(SecretString::new(seed.trim().to_string()))
}

fn prompt_new_password_for_unlock() -> Result<SecretString, CliError> {
    let password = rpassword::prompt_password("Master password: ").map_err(CliError::Io)?;
    Ok(SecretString::new(password))
}

fn verify_totp_setup(label: &str, seed: &SecretString) -> Result<(), CliError> {
    println!(
        "Verify {label}: scan the QR above or enter the seed in your app, \
         then type the 6-digit code from the app (not from vault)."
    );
    let entered =
        rpassword::prompt_password("Authenticator code (6 digits): ").map_err(CliError::Io)?;
    if !verify_totp(seed, entered.trim())? {
        return Err(CliError::TotpSetupVerifyFailed {
            label: label.to_string(),
        });
    }
    println!("{label} authenticator verified.");
    Ok(())
}

fn setup_and_verify_authenticator(
    label: &str,
    seed: &SecretString,
    layout: &VaultLayout,
) -> Result<(), CliError> {
    println!();
    println!("== {label} authenticator ==");
    println!("Generating {label} otpauth URI and terminal QR...");
    fs::create_dir_all(&layout.root)?;

    let uri = otpauth_uri_for_vault_seed(label, seed)?;

    println!("Save this {label} seed offline after you verify it:");
    println!("{}", seed.expose_secret());
    println!();
    println!("{label} otpauth URI (manual entry):");
    println!("{uri}");
    println!();
    println!("{label} QR (scan with your app):");
    println!("{}", vault_totp::qr_ascii(&uri)?);
    println!();

    verify_totp_setup(label, seed)
}

fn otpauth_uri_for_vault_seed(account: &str, seed: &SecretString) -> Result<String, CliError> {
    let secret = Secret::Encoded(seed.expose_secret().to_string())
        .to_bytes()
        .map_err(|_| CliError::Config("invalid generated TOTP seed".into()))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        0,
        30,
        secret,
        Some("Vault".into()),
        account.into(),
    )
    .map_err(|_| CliError::Config("invalid generated TOTP seed".into()))?;
    Ok(totp.get_url())
}

fn generate_totp_seed() -> SecretString {
    let encoded = match Secret::generate_secret().to_encoded() {
        Secret::Encoded(s) => s,
        Secret::Raw(raw) => match Secret::Raw(raw).to_encoded() {
            Secret::Encoded(s) => s,
            Secret::Raw(_) => String::new(),
        },
    };
    SecretString::new(encoded)
}

fn empty_backup_data() -> BackupData {
    BackupData {
        passwords: PasswordsDocument::empty(),
        envs: HashMap::new(),
        files: Vec::new(),
        totp: TotpDocument::empty(),
    }
}

fn load_backup_data(layout: &VaultLayout, data_key: &SecretString) -> Result<BackupData, CliError> {
    let passwords = if layout.passwords.is_file() {
        PasswordStore::load_path(data_key, &layout.passwords)?
            .document()
            .clone()
    } else {
        PasswordsDocument::empty()
    };

    let mut envs = HashMap::new();
    let env_vault = EnvVault::new(&layout.envs_dir);
    for name in env_vault.list_profiles()? {
        let store = env_vault.load_profile(&name, data_key)?;
        envs.insert(name, store.document().clone());
    }

    let file_vault = FileVault::new(&layout.files_dir);
    let mut files = Vec::new();
    for name in file_vault.list()? {
        let bytes = file_vault.decrypt_stdout(&name, data_key)?;
        files.push(BackupFileEntry {
            name,
            data_base64: STANDARD.encode(bytes),
        });
    }

    let totp = if layout.totp.is_file() {
        TotpStore::load_path(data_key, &layout.totp)?
            .document()
            .clone()
    } else {
        TotpDocument::empty()
    };

    Ok(BackupData {
        passwords,
        envs,
        files,
        totp,
    })
}

fn re_encrypt_ssh_store(
    layout: &VaultLayout,
    old_key: &SecretString,
    new_key: &SecretString,
) -> Result<(), CliError> {
    use vault_ssh::SshStore;
    if !layout.ssh.is_file() {
        return Ok(());
    }
    let store = SshStore::load_path(old_key, &layout.ssh).map_err(CliError::from)?;
    store.save_path(new_key, &layout.ssh).map_err(CliError::from)
}

fn reset_ssh_store(layout: &VaultLayout, data_key: &SecretString) -> Result<(), CliError> {
    use vault_ssh::SshStore;
    if layout.ssh.is_file() {
        SshStore::empty()
            .save_path(data_key, &layout.ssh)
            .map_err(CliError::from)?;
    }
    Ok(())
}

fn restore_backup_data(
    layout: &VaultLayout,
    data_key: &SecretString,
    data: BackupData,
) -> Result<(), CliError> {
    fs::create_dir_all(&layout.root)?;
    PasswordStore::from_document(data.passwords).save_path(data_key, &layout.passwords)?;
    TotpStore::from_document(data.totp).save_path(data_key, &layout.totp)?;

    fs::create_dir_all(&layout.envs_dir)?;
    let env_vault = EnvVault::new(&layout.envs_dir);
    for existing in env_vault.list_profiles()? {
        env_vault.remove_profile(&existing)?;
    }
    for (name, doc) in data.envs {
        let store = vault_envs::ProfileStore::from_document(doc);
        if store.profile_name() != name {
            // profile field inside doc is authoritative
        }
        env_vault.save_profile(&store, data_key)?;
    }

    fs::create_dir_all(&layout.files_dir)?;
    let file_vault = FileVault::new(&layout.files_dir);
    for existing in file_vault.list()? {
        file_vault.remove(&existing)?;
    }
    for entry in data.files {
        let bytes = STANDARD
            .decode(&entry.data_base64)
            .map_err(|_| CliError::Config("invalid backup file payload".into()))?;
        let ciphertext = encrypt(data_key, &bytes)?;
        fs::write(layout.files_dir.join(&entry.name), ciphertext)?;
    }
    Ok(())
}

fn write_backup(
    payload: &BackupPayload,
    backup_key: &SecretString,
    layout: &VaultLayout,
) -> Result<(), CliError> {
    let plaintext = serde_json::to_vec(payload)?;
    let ciphertext = encrypt(backup_key, &plaintext)?;
    fs::write(&layout.backup, ciphertext)?;
    Ok(())
}

fn read_backup(layout: &VaultLayout, backup_key: &SecretString) -> Result<BackupPayload, CliError> {
    let ciphertext = fs::read(&layout.backup)?;
    let plaintext = decrypt(backup_key, &ciphertext)?;
    let payload: BackupPayload = serde_json::from_slice(&plaintext)?;
    if payload.version != BACKUP_VERSION {
        return Err(CliError::Config("unsupported backup version".into()));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use vault_core::salt_from_lock;
    use vault_passwords::{NewEntry, PasswordStore};

    fn test_config(root: &std::path::Path) -> Config {
        let mut config = Config::default();
        config.vault.path = root.to_path_buf();
        config.vault.lock = Some("test-lock-for-unit-tests".into());
        config.vault.device_id = Some(crate::device::compute_device_id().unwrap());
        config.kdf.memory_cost = 256;
        config.kdf.time_cost = 1;
        config.kdf.parallelism = 1;
        config
    }

    #[test]
    fn init_writes_decryptable_stores_and_nvlt_enc() {
        let root = std::env::temp_dir().join(format!("vault-init-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut config = test_config(&root);
        let layout = VaultLayout::from_config(&config);

        let password = SecretString::new("init-pass".into());
        let primary = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
        let backup = SecretString::new("MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK".into());
        init_with_secrets(&mut config, &password, &primary, &backup).unwrap();

        assert!(layout.passwords.is_file());
        assert!(layout.has_rate_duplas());

        let salt = salt_from_lock(config.lock_str().unwrap()).unwrap();
        let data_key =
            vault_core::derive_key(&password, &primary, &salt, config.kdf.to_kdf_params()).unwrap();
        PasswordStore::load_path(&data_key, &layout.passwords).unwrap();

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backup_then_recover_with_new_primary() {
        let root = std::env::temp_dir().join(format!("vault-life-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut config = test_config(&root);
        let layout = VaultLayout::from_config(&config);

        let password = SecretString::new("master-pass".into());
        let primary = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
        let backup = SecretString::new("MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK".into());
        init_with_secrets(&mut config, &password, &primary, &backup).unwrap();

        let salt = salt_from_lock(config.lock_str().unwrap()).unwrap();
        let data_key =
            vault_core::derive_key(&password, &primary, &salt, config.kdf.to_kdf_params()).unwrap();
        let mut store = PasswordStore::load_path(&data_key, &layout.passwords).unwrap();
        store
            .add(NewEntry {
                domain: "example.com".into(),
                username: "user".into(),
                password: "secret".into(),
                totp: None,
                notes: String::new(),
                fields: vec![],
            })
            .unwrap();
        store.save_path(&data_key, &layout.passwords).unwrap();

        let snapshot = load_backup_data(&layout, &data_key).unwrap();
        let backup_key =
            vault_core::derive_key(&password, &backup, &salt, config.kdf.to_kdf_params()).unwrap();
        write_backup(
            &BackupPayload {
                version: BACKUP_VERSION,
                data: snapshot,
                created_at: Utc::now(),
            },
            &backup_key,
            &layout,
        )
        .unwrap();

        let new_primary = generate_totp_seed();
        let payload = read_backup(&layout, &backup_key).unwrap();
        let new_data_key =
            vault_core::derive_key(&password, &new_primary, &salt, config.kdf.to_kdf_params())
                .unwrap();
        restore_backup_data(&layout, &new_data_key, payload.data).unwrap();
        let kdf_params = config.kdf.to_kdf_params();
        remint_with_new_keypair(
            &mut config,
            &layout,
            &password,
            &new_primary,
            &backup,
            kdf_params,
        )
        .unwrap();

        let unlocked = PasswordStore::load_path(&new_data_key, &layout.passwords).unwrap();
        assert_eq!(
            unlocked.get("example.com", "user").unwrap().password,
            "secret"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rotate_reencrypts_data_and_nvlt_enc() {
        let root = std::env::temp_dir().join(format!("vault-rotate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut config = test_config(&root);
        let layout = VaultLayout::from_config(&config);

        let old_password = SecretString::new("master-pass".into());
        let old_primary = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
        let old_backup = SecretString::new("MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK".into());
        init_with_secrets(&mut config, &old_password, &old_primary, &old_backup).unwrap();

        let salt = salt_from_lock(config.lock_str().unwrap()).unwrap();
        let params = config.kdf.to_kdf_params();
        let old_data_key =
            vault_core::derive_key(&old_password, &old_primary, &salt, params).unwrap();

        let mut store = PasswordStore::load_path(&old_data_key, &layout.passwords).unwrap();
        store
            .add(NewEntry {
                domain: "rotate.test".into(),
                username: "me".into(),
                password: "pw".into(),
                totp: None,
                notes: String::new(),
                fields: vec![],
            })
            .unwrap();
        store.save_path(&old_data_key, &layout.passwords).unwrap();

        use vault_ssh::{NewSshEntry, SshStore};
        let mut ssh = SshStore::empty();
        ssh.add(NewSshEntry {
            name: "testkey".into(),
            private_pem: "fake-private".into(),
            public_openssh: "fake-public".into(),
            host: None,
            user: None,
        })
        .unwrap();
        ssh.save_path(&old_data_key, &layout.ssh).unwrap();

        let snapshot = load_backup_data(&layout, &old_data_key).unwrap();
        let new_password = SecretString::new("new-master".into());
        let new_primary = generate_totp_seed();
        let new_backup = generate_totp_seed();
        let new_data_key =
            vault_core::derive_key(&new_password, &new_primary, &salt, params).unwrap();
        let new_backup_key =
            vault_core::derive_key(&new_password, &new_backup, &salt, params).unwrap();

        restore_backup_data(&layout, &new_data_key, snapshot).unwrap();
        re_encrypt_ssh_store(&layout, &old_data_key, &new_data_key).unwrap();
        let params = config.kdf.to_kdf_params();
        remint_with_new_keypair(
            &mut config,
            &layout,
            &new_password,
            &new_primary,
            &new_backup,
            params,
        )
        .unwrap();

        let loaded = PasswordStore::load_path(&new_data_key, &layout.passwords).unwrap();
        assert_eq!(
            loaded.get("rotate.test", "me").unwrap().password,
            "pw"
        );
        let ssh_loaded = SshStore::load_path(&new_data_key, &layout.ssh).unwrap();
        assert!(ssh_loaded.list().any(|e| e.name == "testkey"));

        write_backup(
            &BackupPayload {
                version: BACKUP_VERSION,
                data: load_backup_data(&layout, &new_data_key).unwrap(),
                created_at: Utc::now(),
            },
            &new_backup_key,
            &layout,
        )
        .unwrap();

        let _ = fs::remove_dir_all(&root);
    }
}
