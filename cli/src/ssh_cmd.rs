use std::fs;
use std::path::PathBuf;

use vault_ssh::{NewSshEntry, SshStore};

use crate::config::set_private_file_permissions;
use crate::confirm::confirm_or_cancel;
use crate::error::CliError;
use crate::paths::VaultLayout;
use crate::unlock::UnlockSession;

fn ssh_dir() -> PathBuf {
    directories::UserDirs::new()
        .map(|u| u.home_dir().join(".ssh"))
        .unwrap_or_else(|| PathBuf::from(".ssh"))
}

fn key_paths(name: &str) -> Result<(PathBuf, PathBuf), CliError> {
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err(CliError::Config(
            "SSH entry name must be non-empty and must not contain path separators".into(),
        ));
    }
    let dir = ssh_dir();
    Ok((dir.join(name), dir.join(format!("{name}.pub"))))
}

fn load_store(session: &UnlockSession, layout: &VaultLayout) -> Result<SshStore, CliError> {
    if layout.ssh.is_file() {
        SshStore::load_path(&session.data_key, &layout.ssh).map_err(CliError::from)
    } else {
        Ok(SshStore::empty())
    }
}

fn save_store(
    store: &SshStore,
    session: &UnlockSession,
    layout: &VaultLayout,
) -> Result<(), CliError> {
    store
        .save_path(&session.data_key, &layout.ssh)
        .map_err(CliError::from)?;
    set_private_file_permissions(&layout.ssh)?;
    Ok(())
}

pub fn register(
    config: &crate::config::Config,
    name: String,
    private_path: PathBuf,
    public_path: Option<PathBuf>,
) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    let session = UnlockSession::unlock_data_key(config, &layout)?;
    let private_pem = fs::read_to_string(&private_path)?;
    let public_openssh = if let Some(p) = public_path {
        fs::read_to_string(p)?
    } else {
        let guess = private_path.with_extension("pub");
        fs::read_to_string(guess).map_err(CliError::Io)?
    };
    let mut store = load_store(&session, &layout)?;
    store.add(NewSshEntry {
        name: name.clone(),
        private_pem,
        public_openssh,
        host: None,
        user: None,
    })?;
    save_store(&store, &session, &layout)?;
    println!("Registered SSH key '{name}'.");
    Ok(())
}

pub fn list(config: &crate::config::Config) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    let session = UnlockSession::unlock_data_key(config, &layout)?;
    let store = load_store(&session, &layout)?;
    for entry in store.list() {
        println!("{}", entry.name);
    }
    Ok(())
}

pub fn activate(config: &crate::config::Config, name: &str) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    let session = UnlockSession::unlock_data_key(config, &layout)?;
    let mut store = load_store(&session, &layout)?;
    let (priv_path, pub_path) = key_paths(name)?;
    fs::create_dir_all(ssh_dir())?;
    {
        let entry = store.get_mut(name)?;
        fs::write(&priv_path, &entry.private_pem)?;
        fs::write(&pub_path, &entry.public_openssh)?;
        set_private_file_permissions(&priv_path)?;
        entry.installed_paths = vec![
            priv_path.display().to_string(),
            pub_path.display().to_string(),
        ];
    }
    save_store(&store, &session, &layout)?;
    println!("Activated '{name}' at {}", priv_path.display());
    Ok(())
}

pub fn deactivate(config: &crate::config::Config, name: &str) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    let session = UnlockSession::unlock_data_key(config, &layout)?;
    let mut store = load_store(&session, &layout)?;
    let paths: Vec<PathBuf> = {
        let entry = store.get_mut(name)?;
        entry.installed_paths.drain(..).map(PathBuf::from).collect()
    };
    for p in paths {
        let _ = fs::remove_file(p);
    }
    save_store(&store, &session, &layout)?;
    println!("Deactivated '{name}'.");
    Ok(())
}

pub fn remove(config: &crate::config::Config, name: &str) -> Result<(), CliError> {
    confirm_or_cancel(&format!(
        "Remove SSH entry '{name}' from the vault? [y/N]: "
    ))?;
    let layout = VaultLayout::from_config(config);
    let session = UnlockSession::unlock_data_key(config, &layout)?;
    let mut store = load_store(&session, &layout)?;
    let _ = store.remove(name)?;
    save_store(&store, &session, &layout)?;
    Ok(())
}

pub fn open(config: &crate::config::Config, name: &str) -> Result<(), CliError> {
    activate(config, name)?;
    let layout = VaultLayout::from_config(config);
    let session = UnlockSession::unlock_data_key(config, &layout)?;
    let store = load_store(&session, &layout)?;
    let entry = store
        .list()
        .find(|e| e.name == name)
        .ok_or_else(|| CliError::Config(format!("SSH entry not found: {name}")))?;
    let (priv_path, _) = key_paths(name)?;
    if let (Some(host), Some(user)) = (&entry.host, &entry.user) {
        println!("ssh -i {} {user}@{host}", priv_path.display());
    } else {
        println!("Key ready: {}", priv_path.display());
    }
    Ok(())
}
