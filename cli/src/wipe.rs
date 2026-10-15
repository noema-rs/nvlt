use std::fs;

use crate::config::Config;
use crate::error::CliError;
use crate::paths::VaultLayout;

/// Clear initialization secrets from vault-local config (keeps path and KDF).
pub fn clear_vault_init_config(config: &mut Config) {
    config.vault.lock = None;
}

/// Remove operational vault ciphertext and any legacy v1 artifacts.
pub fn wipe_operational_vault(config: &Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    let _ = crate::agent::lock();
    remove_if_exists(&layout.passwords)?;
    remove_if_exists(&layout.totp)?;
    remove_if_exists(&layout.backup)?;
    remove_if_exists(&layout.ssh)?;
    remove_if_exists(&layout.legacy_nvlt_enc())?;
    remove_dir_if_exists(&layout.envs_dir)?;
    remove_dir_if_exists(&layout.files_dir)?;
    Ok(())
}

fn remove_if_exists(path: &std::path::Path) -> Result<(), CliError> {
    if path.is_file() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn remove_dir_if_exists(path: &std::path::Path) -> Result<(), CliError> {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    #[test]
    fn clear_vault_init_config_clears_secrets_only() {
        let mut config = Config::default();
        config.vault.path = PathBuf::from("/tmp/v");
        config.vault.lock = Some("lock".into());
        config.kdf.memory_cost = 1234;

        clear_vault_init_config(&mut config);

        assert_eq!(config.vault.path, PathBuf::from("/tmp/v"));
        assert_eq!(config.kdf.memory_cost, 1234);
        assert!(config.vault.lock.is_none());
    }
}
