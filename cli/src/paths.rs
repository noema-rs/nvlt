use std::path::PathBuf;

use crate::config::{Config, VAULT_CONFIG_FILE};

#[derive(Debug, Clone)]
pub struct VaultLayout {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub passwords: PathBuf,
    pub envs_dir: PathBuf,
    pub files_dir: PathBuf,
    pub totp: PathBuf,
    pub backup: PathBuf,
    pub ssh: PathBuf,
}

pub const SSH_STORE_FILE: &str = "ssh.age";

impl VaultLayout {
    pub fn from_config(config: &Config) -> Self {
        let root = config.vault.path.clone();
        Self {
            config_file: root.join(VAULT_CONFIG_FILE),
            passwords: root.join(&config.vault.password_file),
            envs_dir: root.join(&config.vault.envs_dir),
            files_dir: root.join(&config.vault.files_dir),
            totp: root.join(&config.vault.totp_file),
            backup: root.join(&config.vault.backup_file),
            ssh: root.join(SSH_STORE_FILE),
            root,
        }
    }

    /// Legacy local seed blob from v1; removed when encountered.
    pub fn legacy_nvlt_enc(&self) -> PathBuf {
        self.root.join("nvlt.enc")
    }

    pub fn is_initialized(&self, config: &Config) -> bool {
        config.vault.lock.as_ref().is_some_and(|s| !s.is_empty()) && self.passwords.is_file()
    }
}
