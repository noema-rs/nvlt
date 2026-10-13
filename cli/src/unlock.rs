use secrecy::SecretString;
use vault_core::{derive_key, verify_totp};
use vault_passwords::PasswordStore;

use crate::agent;
use crate::config::Config;
use crate::error::CliError;
use crate::paths::VaultLayout;
use rpassword::prompt_password;
use crate::rate_limit::{self, burn_slot, load_primary_from_slot, rewrap_slot_after_success, select_active_slot};

pub struct UnlockSession {
    pub(crate) password: SecretString,
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
        rate_limit::guard_device(config)?;
        rate_limit::ensure_rate_layout(config, layout)?;
        let slot = select_active_slot(layout, config)?;
        let salt = vault_salt(config)?;
        let params = config.kdf.to_kdf_params();
        let password =
            SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?);

        let (primary, backup) = match load_primary_from_slot(layout, config, slot, &password, params)
        {
            Ok(seeds) => seeds,
            Err(e) => {
                let _ = burn_slot(layout, slot);
                return Err(e);
            }
        };

        let code = prompt_password("Authenticator code (6 digits): ").map_err(CliError::Io)?;
        if !verify_totp(&primary, code.trim())? {
            eprintln!(
                "Authenticator code did not match. If you re-initialized the vault, \
                 use the new primary entry from init (not an old app label)."
            );
            let _ = burn_slot(layout, slot);
            return Err(CliError::UnlockCancelled);
        }

        let data_key = derive_key(&password, &primary, &salt, params).map_err(|e| {
            let _ = burn_slot(layout, slot);
            CliError::from(e)
        })?;
        if !data_key_matches_vault(layout, &data_key) {
            eprintln!(
                "Credentials verified, but encrypted vault files could not be opened.\n\
                 Check `nvlt config show` paths match files under {}.",
                layout.root.display()
            );
            let _ = burn_slot(layout, slot);
            return Err(CliError::UnlockCancelled);
        }

        if rewrap_slot_after_success(layout, config, slot, &password, &primary, &backup, params)
            .is_err()
        {
            let _ = burn_slot(layout, slot);
            return Err(CliError::UnlockCancelled);
        }

        Ok(Self { password, data_key })
    }

    pub fn derive_backup_key(
        &self,
        config: &Config,
        layout: &VaultLayout,
    ) -> Result<SecretString, CliError> {
        let salt = vault_salt(config)?;
        let params = config.kdf.to_kdf_params();
        let code =
            prompt_password("Backup authenticator code (6 digits): ").map_err(CliError::Io)?;
        let password = if self.password.expose_secret().is_empty() {
            SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?)
        } else {
            self.password.clone()
        };
        rate_limit::guard_device(config)?;
        rate_limit::ensure_rate_layout(config, layout)?;
        let slot = select_active_slot(layout, config)?;
        let (_primary, backup) =
            load_primary_from_slot(layout, config, slot, &password, params)?;
        if !verify_totp(&backup, code.trim())? {
            let _ = burn_slot(layout, slot);
            return Err(CliError::UnlockCancelled);
        }
        derive_key(&password, &backup, &salt, params).map_err(CliError::from)
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

use secrecy::ExposeSecret;
