use std::collections::HashMap;
use std::fs;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use rpassword::prompt_password;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use vault_core::{decrypt, derive_key, encrypt, generate_identity};
use vault_envs::EnvVault;
use vault_files::FileVault;
use vault_passwords::{PasswordStore, PasswordsDocument};
use vault_totp::{TotpDocument, TotpStore};

use crate::config::{generate_lock_string, Config};
use crate::confirm::{confirm, confirm_or_cancel};
use crate::error::CliError;
use crate::keys;
use crate::paths::VaultLayout;
use crate::unlock::{prompt_new_password, vault_salt, UnlockSession};

const BACKUP_VERSION: u32 = 3;

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
    println!(
        "  lock:      {}",
        config.vault.lock.as_deref().unwrap_or("(unset)")
    );
    println!("  passwords: {}", flag(layout.passwords.is_file()));
    println!("  totp:      {}", flag(layout.totp.is_file()));
    println!("  backup:    {}", flag(layout.backup.is_file()));
    println!("  ssh:       {}", flag(layout.ssh.is_file()));
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
    if vault_has_ciphertext(&layout) {
        return Err(CliError::Config(format!(
            "encrypted vault files already exist under {}; init would overwrite them.\n\
             Re-initializing without your password, keys, or backup causes data loss.\n\
             Use `nvlt system init --from-snapshot` or `nvlt system recover` instead.",
            layout.root.display()
        )));
    }

    config.vault.lock = Some(generate_lock_string());

    let password = prompt_new_password()?;

    println!("Generating main and backup unlock keys...");
    let (main_secret, main_public) = generate_identity()?;
    let (backup_secret, backup_public) = generate_identity()?;

    let main_path = keys::prompt_key_path("Main unlock key file path: ")?;
    keys::warn_key_custody(&layout, &main_path);
    let backup_path = keys::prompt_key_path("Backup unlock key file path: ")?;
    keys::warn_key_custody(&layout, &backup_path);

    println!("Creating vault configuration and encrypted data files...");
    init_with_secrets(config, &password, &main_secret, &backup_secret)?;
    crate::config::save_config(config)?;

    keys::write_identity_file(&main_path, &main_secret, None)?;
    keys::write_identity_file(&backup_path, &backup_secret, None)?;
    let _ = crate::agent::lock();

    println!();
    println!("Vault initialized at {}", layout.root.display());
    println!(
        "Main unlock key:   {}  ({main_public})",
        main_path.display()
    );
    println!(
        "Backup unlock key: {}  ({backup_public})",
        backup_path.display()
    );
    println!();
    println!("Store the BACKUP key strictly offline. It is required for `nvlt system backup` and `nvlt system recover`.");
    println!("Keep the main key off this machine when possible.");
    Ok(())
}

pub fn init_from_snapshot(
    bundle_dir: std::path::PathBuf,
    identity_path: std::path::PathBuf,
) -> Result<(), CliError> {
    let config = crate::config::load_config()?;
    crate::snapshot::materialize_snapshot(&config, &bundle_dir, &identity_path)?;

    let config = crate::config::load_config()?;
    let layout = VaultLayout::from_config(&config);
    if !layout.passwords.is_file() {
        return Err(CliError::Config(
            "no encrypted vault data found after snapshot extract; check the snapshot bundle"
                .into(),
        ));
    }
    config
        .lock_str()
        .map_err(|_| CliError::Config("config.toml missing lock after snapshot extract".into()))?;

    let password = SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?);
    let key_path = keys::prompt_key_path("Main unlock key file path: ")?;
    keys::warn_key_custody(&layout, &key_path);
    let key_secret = keys::load_identity_checked(&key_path)?;

    let salt = vault_salt(&config)?;
    let params = config.kdf.to_kdf_params();
    let data_key = derive_key(&password, &key_secret, &salt, params)?;
    if PasswordStore::load_path(&data_key, &layout.passwords).is_err() {
        return Err(CliError::Config(
            "credentials did not decrypt existing vault data; \
             check the master password and main key, or recover with your backup key"
                .into(),
        ));
    }

    println!("Vault ready at {}.", layout.root.display());
    println!("Unlock with your master password and main key, or recover with the backup key if the main key is lost.");
    Ok(())
}

pub(crate) fn init_with_secrets(
    config: &mut Config,
    password: &SecretString,
    main_secret: &SecretString,
    backup_secret: &SecretString,
) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    if layout.is_initialized(config) {
        return Err(CliError::AlreadyInitialized {
            vault_root: layout.root.clone(),
        });
    }

    fs::create_dir_all(&layout.root)?;

    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();
    let data_key = derive_key(password, main_secret, &salt, params)?;
    let backup_key = derive_key(password, backup_secret, &salt, params)?;

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

    if layout.backup.is_file() {
        read_backup(&layout, &backup_key).map_err(|_| {
            CliError::Config(
                "backup key or master password did not open the existing backup.age; \
                 check the backup key file"
                    .into(),
            )
        })?;
    }

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
        "⚠️  You are about to recover your vault using the backup unlock key.\n\
            A new main unlock key will be generated and your current vault files will be REPLACED.\n\
         \n\
            Continue? [y/N]: ",
    )?;

    let password = SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?);
    let backup_path = keys::prompt_key_path("Backup key file path: ")?;
    keys::warn_key_custody(&layout, &backup_path);
    let backup_secret = keys::load_identity_checked(&backup_path)?;

    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();
    let backup_key = derive_key(&password, &backup_secret, &salt, params)?;
    let payload = read_backup(&layout, &backup_key).map_err(|_| {
        CliError::Config("backup key or master password did not decrypt backup.age".into())
    })?;

    let (new_main_secret, new_main_public) = generate_identity()?;
    let new_main_path = keys::prompt_key_path("New main unlock key file path: ")?;
    keys::warn_key_custody(&layout, &new_main_path);

    let data_key = derive_key(&password, &new_main_secret, &salt, params)?;
    restore_backup_data(&layout, &data_key, payload.data)?;
    reset_ssh_store(&layout, &data_key)?;
    keys::write_identity_file(&new_main_path, &new_main_secret, None)?;

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
    println!("Recovery complete. The old main key no longer opens the vault.");
    println!(
        "New main unlock key: {}  ({new_main_public})",
        new_main_path.display()
    );
    Ok(())
}

pub fn rotate(config: &Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    confirm_or_cancel(
        "⚠️  You are about to rotate your credentials.\n\
            This re-encrypts all vault files and can change your master password and unlock keys.\n\
            Old credentials will no longer work.\n\
         \n\
            Continue? [y/N]: ",
    )?;

    let session = UnlockSession::unlock_interactive(config, &layout)?;

    let new_password = if confirm("Change master password? [y/N]: ")? {
        prompt_new_password()?
    } else {
        session.password.clone()
    };

    let (main_secret, new_main_path) = if confirm("Generate a new main unlock key? [y/N]: ")? {
        let (secret, public) = generate_identity()?;
        let path = keys::prompt_key_path("New main unlock key file path: ")?;
        keys::warn_key_custody(&layout, &path);
        keys::write_identity_file(&path, &secret, None)?;
        println!("New main unlock key: {}  ({public})", path.display());
        (secret, Some(path))
    } else {
        (session.key_secret.clone(), None)
    };

    let (backup_secret, new_backup_path) = if confirm("Generate a new backup unlock key? [y/N]: ")?
    {
        let (secret, public) = generate_identity()?;
        let path = keys::prompt_key_path("New backup unlock key file path: ")?;
        keys::warn_key_custody(&layout, &path);
        keys::write_identity_file(&path, &secret, None)?;
        println!("New backup unlock key: {}  ({public})", path.display());
        (secret, Some(path))
    } else {
        let path = keys::prompt_key_path("Current backup key file path: ")?;
        keys::warn_key_custody(&layout, &path);
        (keys::load_identity_checked(&path)?, None)
    };

    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();
    let data_key = derive_key(&new_password, &main_secret, &salt, params)?;
    let backup_key = derive_key(&new_password, &backup_secret, &salt, params)?;

    let snapshot = load_backup_data(&layout, &session.data_key)?;
    restore_backup_data(&layout, &data_key, snapshot)?;
    re_encrypt_ssh_store(&layout, &session.data_key, &data_key)?;

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
    println!("Rotation complete.");
    if new_main_path.is_none() && new_backup_path.is_none() {
        println!("Reuse your existing main and backup key files with the new credentials.");
    }
    println!("Store the backup key strictly offline; old credentials no longer work.");
    Ok(())
}

fn vault_has_ciphertext(layout: &VaultLayout) -> bool {
    layout.passwords.is_file()
        || layout.totp.is_file()
        || layout.backup.is_file()
        || layout.ssh.is_file()
        || layout.envs_dir.is_dir()
        || layout.files_dir.is_dir()
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
    store
        .save_path(new_key, &layout.ssh)
        .map_err(CliError::from)
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
        config.kdf.memory_cost = 256;
        config.kdf.time_cost = 1;
        config.kdf.parallelism = 1;
        config
    }

    fn secrets() -> (SecretString, SecretString, SecretString) {
        (
            SecretString::new("master-pass".into()),
            SecretString::new("AGE-SECRET-KEY-1TESTMAINKEY".into()),
            SecretString::new("AGE-SECRET-KEY-1TESTBACKUPKEY".into()),
        )
    }

    #[test]
    fn init_writes_decryptable_stores_without_rate_dir() {
        let root = std::env::temp_dir().join(format!("vault-init-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut config = test_config(&root);
        let layout = VaultLayout::from_config(&config);

        let (password, main_secret, backup_secret) = secrets();
        init_with_secrets(&mut config, &password, &main_secret, &backup_secret).unwrap();

        assert!(layout.passwords.is_file());
        assert!(layout.backup.is_file());
        assert!(!layout.root.join("rate").exists());
        assert!(!layout.legacy_nvlt_enc().exists());

        let salt = salt_from_lock(config.lock_str().unwrap()).unwrap();
        let data_key =
            derive_key(&password, &main_secret, &salt, config.kdf.to_kdf_params()).unwrap();
        PasswordStore::load_path(&data_key, &layout.passwords).unwrap();

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backup_then_recover_with_new_main_key() {
        let root = std::env::temp_dir().join(format!("vault-life-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut config = test_config(&root);
        let layout = VaultLayout::from_config(&config);

        let (password, main_secret, backup_secret) = secrets();
        init_with_secrets(&mut config, &password, &main_secret, &backup_secret).unwrap();

        let salt = salt_from_lock(config.lock_str().unwrap()).unwrap();
        let params = config.kdf.to_kdf_params();
        let data_key = derive_key(&password, &main_secret, &salt, params).unwrap();
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
        let backup_key = derive_key(&password, &backup_secret, &salt, params).unwrap();
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

        let new_main = SecretString::new("AGE-SECRET-KEY-1ROTATEDMAINKEY".into());
        let payload = read_backup(&layout, &backup_key).unwrap();
        let new_data_key = derive_key(&password, &new_main, &salt, params).unwrap();
        restore_backup_data(&layout, &new_data_key, payload.data).unwrap();

        let unlocked = PasswordStore::load_path(&new_data_key, &layout.passwords).unwrap();
        assert_eq!(
            unlocked.get("example.com", "user").unwrap().password,
            "secret"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rotate_reencrypts_data_and_backup() {
        let root = std::env::temp_dir().join(format!("vault-rotate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut config = test_config(&root);
        let layout = VaultLayout::from_config(&config);

        let (old_password, old_main, old_backup) = secrets();
        init_with_secrets(&mut config, &old_password, &old_main, &old_backup).unwrap();

        let salt = salt_from_lock(config.lock_str().unwrap()).unwrap();
        let params = config.kdf.to_kdf_params();
        let old_data_key = derive_key(&old_password, &old_main, &salt, params).unwrap();

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
        let new_main = SecretString::new("AGE-SECRET-KEY-1NEWMAINKEY".into());
        let new_backup = SecretString::new("AGE-SECRET-KEY-1NEWBACKUPKEY".into());
        let new_data_key = derive_key(&new_password, &new_main, &salt, params).unwrap();
        let new_backup_key = derive_key(&new_password, &new_backup, &salt, params).unwrap();

        restore_backup_data(&layout, &new_data_key, snapshot).unwrap();
        re_encrypt_ssh_store(&layout, &old_data_key, &new_data_key).unwrap();

        let loaded = PasswordStore::load_path(&new_data_key, &layout.passwords).unwrap();
        assert_eq!(loaded.get("rotate.test", "me").unwrap().password, "pw");
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
