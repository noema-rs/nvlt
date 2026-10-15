use secrecy::{ExposeSecret, SecretString};
use vault_core::derive_key;
use vault_passwords::PasswordStore;

use crate::agent;
use crate::config::Config;
use crate::error::CliError;
use crate::keys;
use crate::paths::VaultLayout;
use rpassword::prompt_password;

pub struct UnlockSession {
    pub(crate) password: SecretString,
    pub(crate) key_secret: SecretString,
    pub data_key: SecretString,
}

pub fn vault_salt(config: &Config) -> Result<[u8; 16], CliError> {
    let lock = config.lock_str()?;
    vault_core::salt_from_lock(lock).map_err(CliError::from)
}

impl UnlockSession {
    pub fn unlock_data_key(config: &Config, layout: &VaultLayout) -> Result<Self, CliError> {
        if !layout.is_initialized(config) {
            return Err(CliError::NotInitialized);
        }
        if let Some(data_key) = agent::try_data_key(&layout.root)? {
            if data_key_matches_vault(layout, &data_key) {
                return Ok(Self {
                    password: SecretString::new(String::new()),
                    key_secret: SecretString::new(String::new()),
                    data_key,
                });
            }
            let _ = agent::lock();
            eprintln!("Note: cleared stale nvlt agent session (vault was re-initialized or credentials changed).");
        }
        Self::unlock_interactive(config, layout)
    }

    pub fn unlock_interactive(config: &Config, layout: &VaultLayout) -> Result<Self, CliError> {
        if !layout.is_initialized(config) {
            return Err(CliError::NotInitialized);
        }
        let password =
            SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?);

        let key_path = keys::prompt_key_path("Unlock key file path: ")?;
        keys::warn_key_custody(layout, &key_path);
        let key_secret = keys::load_identity_checked(&key_path)?;

        let salt = vault_salt(config)?;
        let params = config.kdf.to_kdf_params();
        let data_key = derive_key(&password, &key_secret, &salt, params)?;

        if !data_key_matches_vault(layout, &data_key) {
            return Err(CliError::Config(
                "master password or key file did not open the vault; \
                 check both, or recover with your backup key"
                    .into(),
            ));
        }

        Ok(Self {
            password,
            key_secret,
            data_key,
        })
    }

    pub fn derive_backup_key(
        &self,
        config: &Config,
        layout: &VaultLayout,
    ) -> Result<SecretString, CliError> {
        let password = if self.password.expose_secret().is_empty() {
            SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?)
        } else {
            self.password.clone()
        };
        let key_path = keys::prompt_key_path("Backup key file path: ")?;
        keys::warn_key_custody(layout, &key_path);
        let backup_secret = keys::load_identity_checked(&key_path)?;
        let salt = vault_salt(config)?;
        let params = config.kdf.to_kdf_params();
        derive_key(&password, &backup_secret, &salt, params).map_err(CliError::from)
    }
}

pub fn run_unlock(for_duration: &str) -> Result<(), CliError> {
    let config = crate::config::load_config()?;
    let layout = VaultLayout::from_config(&config);
    let ttl = agent::parse_duration(for_duration)?;
    let session = UnlockSession::unlock_interactive(&config, &layout)?;
    agent::ensure_running()?;
    agent::store_session(&layout.root, &session.data_key, ttl)?;
    println!(
        "Session unlocked for {for_duration} (sliding idle timeout). Use `nvlt lock` to clear."
    );
    Ok(())
}

pub fn run_lock() -> Result<(), CliError> {
    agent::lock()?;
    println!("Session locked.");
    Ok(())
}

pub fn prompt_new_password() -> Result<SecretString, CliError> {
    let p1 = prompt_password("New master password: ").map_err(CliError::Io)?;
    let p2 = prompt_password("Confirm master password: ").map_err(CliError::Io)?;
    if p1 != p2 {
        return Err(CliError::Config("passwords do not match".into()));
    }
    Ok(SecretString::new(p1))
}

fn data_key_matches_vault(layout: &VaultLayout, data_key: &SecretString) -> bool {
    PasswordStore::load_path(data_key, &layout.passwords).is_ok()
}
