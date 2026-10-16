use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use vault_core::KdfParams;

use crate::error::CliError;

pub const VAULT_CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootstrapConfig {
    #[serde(default)]
    vault: BootstrapVault,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BootstrapVault {
    #[serde(default = "default_vault_path")]
    path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub vault: VaultSection,
    #[serde(default)]
    pub sync: SyncSection,
    #[serde(default)]
    pub kdf: KdfSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSection {
    #[serde(default = "default_vault_path")]
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<String>,
    #[serde(default = "default_password_file")]
    pub password_file: String,
    #[serde(default = "default_envs_dir")]
    pub envs_dir: String,
    #[serde(default = "default_files_dir")]
    pub files_dir: String,
    #[serde(default = "default_totp_file")]
    pub totp_file: String,
    #[serde(default = "default_backup_file")]
    pub backup_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSection {
    #[serde(default = "default_sync_host_file")]
    pub host_file: String,
    #[serde(default = "default_sync_pub_file")]
    pub pub_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfSection {
    #[serde(default = "default_memory_cost")]
    pub memory_cost: u32,
    #[serde(default = "default_time_cost")]
    pub time_cost: u32,
    #[serde(default = "default_parallelism")]
    pub parallelism: u32,
}

impl Default for VaultSection {
    fn default() -> Self {
        Self {
            path: default_vault_path(),
            lock: None,
            password_file: default_password_file(),
            envs_dir: default_envs_dir(),
            files_dir: default_files_dir(),
            totp_file: default_totp_file(),
            backup_file: default_backup_file(),
        }
    }
}

impl Default for SyncSection {
    fn default() -> Self {
        Self {
            host_file: default_sync_host_file(),
            pub_file: default_sync_pub_file(),
        }
    }
}

impl Default for KdfSection {
    fn default() -> Self {
        Self {
            memory_cost: default_memory_cost(),
            time_cost: default_time_cost(),
            parallelism: default_parallelism(),
        }
    }
}

impl KdfSection {
    pub fn to_kdf_params(&self) -> KdfParams {
        KdfParams {
            memory_cost_kib: self.memory_cost,
            time_cost: self.time_cost,
            parallelism: self.parallelism,
        }
    }
}

impl Config {
    pub fn lock_str(&self) -> Result<&str, CliError> {
        self.vault
            .lock
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or(CliError::NotInitialized)
    }
}

pub fn generate_lock_string() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

fn default_vault_path() -> PathBuf {
    directories::UserDirs::new()
        .map(|u| u.home_dir().join(".nvlt"))
        .unwrap_or_else(|| PathBuf::from(".nvlt"))
}

fn default_password_file() -> String {
    "pass.age".into()
}
fn default_envs_dir() -> String {
    "envs".into()
}
fn default_files_dir() -> String {
    "files".into()
}
fn default_totp_file() -> String {
    "totp.age".into()
}
fn default_backup_file() -> String {
    "backup.age".into()
}
fn default_sync_host_file() -> String {
    "user.age".into()
}
fn default_sync_pub_file() -> String {
    "user.pub".into()
}

fn default_memory_cost() -> u32 {
    262144
}
fn default_time_cost() -> u32 {
    4
}
fn default_parallelism() -> u32 {
    4
}

pub fn bootstrap_config_path() -> PathBuf {
    ProjectDirs::from("", "", "nvlt")
        .map(|d| d.config_dir().join(VAULT_CONFIG_FILE))
        .unwrap_or_else(|| PathBuf::from(VAULT_CONFIG_FILE))
}

pub fn vault_config_path(vault_root: &Path) -> PathBuf {
    vault_root.join(VAULT_CONFIG_FILE)
}

fn read_bootstrap_path() -> Result<PathBuf, CliError> {
    let path = bootstrap_config_path();
    if !path.is_file() {
        return Ok(default_vault_path());
    }
    let text = fs::read_to_string(&path)?;
    let boot: BootstrapConfig =
        toml::from_str(&text).map_err(|e| CliError::Config(e.to_string()))?;
    Ok(boot.vault.path)
}

fn write_bootstrap(vault_path: &Path) -> Result<(), CliError> {
    let path = bootstrap_config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let boot = BootstrapConfig {
        vault: BootstrapVault {
            path: vault_path.to_path_buf(),
        },
    };
    let text = toml::to_string_pretty(&boot).map_err(|e| CliError::Config(e.to_string()))?;
    fs::write(&path, text)?;
    Ok(())
}

pub fn load_config() -> Result<Config, CliError> {
    let vault_path = read_bootstrap_path()?;
    let vault_cfg_path = vault_config_path(&vault_path);
    let mut config = if vault_cfg_path.is_file() {
        let text = fs::read_to_string(&vault_cfg_path)?;
        toml::from_str::<Config>(&text).map_err(|e| CliError::Config(e.to_string()))?
    } else {
        Config::default()
    };
    config.vault.path = vault_path;
    Ok(config)
}

pub fn save_config(config: &Config) -> Result<(), CliError> {
    fs::create_dir_all(&config.vault.path)?;
    let vault_cfg_path = vault_config_path(&config.vault.path);
    let text = toml::to_string_pretty(config).map_err(|e| CliError::Config(e.to_string()))?;
    fs::write(&vault_cfg_path, text)?;
    write_bootstrap(&config.vault.path)?;
    Ok(())
}

pub fn set_config_key(config: &mut Config, key: &str, value: &str) -> Result<(), CliError> {
    match key {
        "vault.path" => config.vault.path = PathBuf::from(value),
        "vault.lock" => config.vault.lock = Some(value.into()),
        "vault.password_file" => config.vault.password_file = value.into(),
        "vault.envs_dir" => config.vault.envs_dir = value.into(),
        "vault.files_dir" => config.vault.files_dir = value.into(),
        "vault.totp_file" => config.vault.totp_file = value.into(),
        "vault.backup_file" => config.vault.backup_file = value.into(),
        "sync.host_file" => config.sync.host_file = value.into(),
        "sync.pub_file" => config.sync.pub_file = value.into(),
        "kdf.memory_cost" => {
            config.kdf.memory_cost = value
                .parse()
                .map_err(|_| CliError::Config("invalid kdf.memory_cost".into()))?;
        }
        "kdf.time_cost" => {
            config.kdf.time_cost = value
                .parse()
                .map_err(|_| CliError::Config("invalid kdf.time_cost".into()))?;
        }
        "kdf.parallelism" => {
            config.kdf.parallelism = value
                .parse()
                .map_err(|_| CliError::Config("invalid kdf.parallelism".into()))?;
        }
        other => return Err(CliError::Config(format!("unknown config key: {other}"))),
    }
    Ok(())
}

pub fn show_config(config: &Config) -> String {
    let mut out = format!(
        "# Bootstrap: {}\n# Vault config: {}\n\n",
        bootstrap_config_path().display(),
        vault_config_path(&config.vault.path).display()
    );
    out.push_str(&toml::to_string_pretty(config).unwrap_or_else(|_| "(invalid config)".into()));
    out
}

#[cfg(unix)]
pub fn set_private_dir_permissions(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
pub fn set_private_file_permissions(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn set_private_dir_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(not(unix))]
pub fn set_private_file_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}
