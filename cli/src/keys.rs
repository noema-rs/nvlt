use std::fs;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::error::CliError;
use crate::paths::VaultLayout;
use crate::prompts::prompt_line;

/// Prompt for the unlock key file path, echoing the typed path on screen.
///
/// The CLI never auto-discovers or reuses a key path.
pub fn prompt_key_path(label: &str) -> Result<PathBuf, CliError> {
    let value = prompt_line(label)?;
    if value.is_empty() {
        return Err(CliError::Config("a key file path is required".into()));
    }
    Ok(expand_tilde(&PathBuf::from(value)))
}

fn expand_tilde(path: &Path) -> PathBuf {
    if let Some(rest) = path.to_string_lossy().strip_prefix("~/") {
        if let Some(home) = directories::UserDirs::new().map(|u| u.home_dir().to_path_buf()) {
            return home.join(rest);
        }
    }
    path.to_path_buf()
}

/// Load an age identity from a key file, prompting for a wrap passphrase when
/// the file is not a plaintext identity.
pub fn load_identity_checked(path: &Path) -> Result<SecretString, CliError> {
    if !path.is_file() {
        return Err(CliError::Config(format!(
            "unlock key file not found: {}",
            path.display()
        )));
    }
    if let Ok(secret) = vault_core::load_identity(path, None) {
        return Ok(secret);
    }
    let passphrase = SecretString::new(
        rpassword::prompt_password("Key file passphrase: ").map_err(CliError::Io)?,
    );
    vault_core::load_identity(path, Some(&passphrase)).map_err(|_| {
        CliError::Config(format!(
            "could not read unlock key from {} (wrong passphrase or malformed key file)",
            path.display()
        ))
    })
}

/// Write a key file, optionally wrapped with a passphrase, with private permissions.
pub fn write_identity_file(
    path: &Path,
    secret: &SecretString,
    wrap_passphrase: Option<&SecretString>,
) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let bytes = match wrap_passphrase {
        Some(passphrase) => vault_core::wrap_identity(secret, passphrase)?,
        None => secret.expose_secret().as_bytes().to_vec(),
    };
    fs::write(path, bytes)?;
    crate::config::set_private_file_permissions(path)?;
    Ok(())
}

/// The `<base>.pub` path that accompanies a key file `base`.
pub fn public_path(base: &Path) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(".pub");
    PathBuf::from(name)
}

/// Write a key pair: the private identity to `base` (private permissions) with
/// its public key as a leading comment, and the public key to `<base>.pub`.
pub fn write_keypair(base: &Path, secret: &SecretString, public: &str) -> Result<(), CliError> {
    if let Some(parent) = base.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let private = format!("# public key: {public}\n{}\n", secret.expose_secret());
    fs::write(base, private)?;
    crate::config::set_private_file_permissions(base)?;
    fs::write(public_path(base), format!("{public}\n"))?;
    Ok(())
}

/// Print a hard custody warning when the key file sits under the vault root or
/// on the same filesystem as the vault.
pub fn warn_key_custody(layout: &VaultLayout, key_path: &Path) {
    let key = resolve_existing(key_path);
    let root = resolve_existing(&layout.root);
    let under_root = !root.as_os_str().is_empty() && key.starts_with(&root);
    let same_fs = match (device_of(&key), device_of(&root)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    if !under_root && !same_fs {
        return;
    }
    eprintln!("⚠️  Key custody warning: unlock key {}", key_path.display());
    if under_root {
        eprintln!("    is inside the vault root {}.", layout.root.display());
    }
    if same_fs {
        eprintln!("    is on the same filesystem as the vault.");
    }
    eprintln!("    Keep the key off this machine (separate media) for real protection.");
}

/// Resolve a path to an existing ancestor where possible, so comparisons work
/// for key files that have not been created yet.
fn resolve_existing(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            match parent.canonicalize() {
                Ok(canonical_parent) => canonical_parent.join(name),
                Err(_) => parent.join(name),
            }
        }
        _ => path.to_path_buf(),
    }
}

#[cfg(unix)]
fn device_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut current = Some(path);
    while let Some(p) = current {
        if let Ok(meta) = fs::metadata(p) {
            return Some(meta.dev());
        }
        current = p.parent();
    }
    None
}

#[cfg(not(unix))]
fn device_of(_path: &Path) -> Option<u64> {
    None
}
