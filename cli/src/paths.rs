use std::path::PathBuf;

use crate::config::{Config, NVLT_ENC_FILE, VAULT_CONFIG_FILE};

#[derive(Debug, Clone)]
pub struct VaultLayout {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub nvlt_enc: PathBuf,
    pub passwords: PathBuf,
    pub envs_dir: PathBuf,
    pub files_dir: PathBuf,
    pub totp: PathBuf,
    pub backup: PathBuf,
    pub ssh: PathBuf,
    pub rate_dir: PathBuf,
}

pub const SSH_STORE_FILE: &str = "ssh.age";
pub const RATE_DIR: &str = "rate";

impl VaultLayout {
    pub fn from_config(config: &Config) -> Self {
        let root = config.vault.path.clone();
        Self {
            config_file: root.join(VAULT_CONFIG_FILE),
            nvlt_enc: root.join(NVLT_ENC_FILE),
            passwords: root.join(&config.vault.password_file),
            envs_dir: root.join(&config.vault.envs_dir),
            files_dir: root.join(&config.vault.files_dir),
            totp: root.join(&config.vault.totp_file),
            backup: root.join(&config.vault.backup_file),
            ssh: root.join(SSH_STORE_FILE),
            rate_dir: root.join(RATE_DIR),
            root,
        }
    }

    pub fn rate_rt_path(&self, slot: u8) -> PathBuf {
        self.rate_dir.join(format!("{slot:02}.rt"))
    }

    pub fn rate_enc_path(&self, slot: u8) -> PathBuf {
        self.rate_dir.join(format!("{slot:02}.enc"))
    }

    pub fn has_rate_duplas(&self) -> bool {
        self.rate_rt_path(1).is_file() && self.rate_enc_path(1).is_file()
    }

    pub fn is_initialized(&self, config: &Config) -> bool {
        config.vault.lock.as_ref().is_some_and(|s| !s.is_empty())
            && self.passwords.is_file()
    }
}
