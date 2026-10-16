use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::{Decryptor, Encryptor, Identity, Recipient};
use age_core::secrecy::{ExposeSecret, SecretString as AgeSecretString};
use tar::{Builder, EntryType, Header};

use crate::config::{
    set_private_dir_permissions, set_private_file_permissions, Config, VAULT_CONFIG_FILE,
};
use crate::confirm::confirm_or_cancel;
use crate::error::CliError;
use crate::lifecycle;
use crate::paths::VaultLayout;

const SYNC_IDENTITY_FILE: &str = "host.key";

fn snapshot_identity_path(snapshot_root: &Path) -> PathBuf {
    snapshot_root.join(".nvlt-sync").join(SYNC_IDENTITY_FILE)
}

fn ensure_snapshot_identity(snapshot_root: &Path) -> Result<age::x25519::Identity, CliError> {
    fs::create_dir_all(snapshot_root.join(".nvlt-sync"))?;
    set_private_dir_permissions(&snapshot_root.join(".nvlt-sync"))?;
    let id_path = snapshot_identity_path(snapshot_root);
    if id_path.is_file() {
        return load_sync_identity_file(&id_path);
    }
    let identity = age::x25519::Identity::generate();
    fs::write(&id_path, identity.to_string().expose_secret().as_bytes())?;
    set_private_file_permissions(&id_path)?;
    Ok(identity)
}

fn load_sync_identity_file(path: &Path) -> Result<age::x25519::Identity, CliError> {
    let text = fs::read_to_string(path)?;
    text.parse::<age::x25519::Identity>()
        .map_err(|e| CliError::Config(e.to_string()))
}

fn resolve_identity_path(snapshot_root: &Path, identity_file: Option<&Path>) -> PathBuf {
    identity_file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| snapshot_identity_path(snapshot_root))
}

pub fn load_sync_identity(
    snapshot_root: &Path,
    identity_file: Option<&Path>,
) -> Result<age::x25519::Identity, CliError> {
    let id_path = resolve_identity_path(snapshot_root, identity_file);
    if !id_path.is_file() {
        return Err(CliError::Config(format!(
            "missing sync private key at {} (use --identity or copy .nvlt-sync/host.key from the export machine)",
            id_path.display()
        )));
    }
    load_sync_identity_file(&id_path)
}

/// Decrypt host.age and extract vault files into the configured vault root.
pub fn materialize_snapshot(
    config: &Config,
    snapshot_root: &Path,
    identity_file: Option<&Path>,
) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    let (host_path, _pub_path) = host_paths(config, snapshot_root);
    if !host_path.is_file() {
        return Err(CliError::Config(format!(
            "missing snapshot host archive at {}",
            host_path.display()
        )));
    }
    if vault_has_overwritable_files(&layout) {
        confirm_or_cancel(
            "⚠️  Import will OVERWRITE existing vault files under the vault root.\n\
                Continue? [y/N]: ",
        )?;
    }

    let host_passphrase =
        rpassword::prompt_password("Sync host passphrase: ").map_err(CliError::Io)?;
    let identity = load_sync_identity(snapshot_root, identity_file)?;
    let ciphertext = fs::read(&host_path)?;
    let plain = decrypt_host_archive(&ciphertext, &host_passphrase, &identity)?;

    fs::create_dir_all(&layout.root)?;
    extract_tar(&plain, &layout.root)?;
    Ok(())
}

fn host_paths(config: &Config, snapshot_root: &Path) -> (PathBuf, PathBuf) {
    (
        snapshot_root.join(&config.sync.host_file),
        snapshot_root.join(&config.sync.pub_file),
    )
}

fn collect_vault_files(
    layout: &VaultLayout,
    config: &Config,
) -> Result<Vec<(String, PathBuf)>, CliError> {
    let mut out = Vec::new();
    out.push((VAULT_CONFIG_FILE.to_string(), layout.config_file.clone()));
    if layout.ssh.is_file() {
        out.push(("ssh.age".to_string(), layout.ssh.clone()));
    }
    for name in [
        &config.vault.password_file,
        &config.vault.totp_file,
        &config.vault.backup_file,
    ] {
        let p = layout.root.join(name);
        if p.is_file() {
            out.push((name.clone(), p));
        }
    }
    if layout.envs_dir.is_dir() {
        for entry in fs::read_dir(&layout.envs_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let rel = format!(
                    "{}/{}",
                    config.vault.envs_dir,
                    entry.file_name().to_string_lossy()
                );
                out.push((rel, entry.path()));
            }
        }
    }
    if layout.files_dir.is_dir() {
        for entry in fs::read_dir(&layout.files_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let rel = format!(
                    "{}/{}",
                    config.vault.files_dir,
                    entry.file_name().to_string_lossy()
                );
                out.push((rel, entry.path()));
            }
        }
    }
    Ok(out)
}

fn build_tar(entries: &[(String, PathBuf)]) -> Result<Vec<u8>, CliError> {
    let mut buf = Vec::new();
    {
        let mut builder = Builder::new(&mut buf);
        for (name, path) in entries {
            let mut file = File::open(path)?;
            let mut header = Header::new_gnu();
            header.set_path(name)?;
            header.set_size(file.metadata()?.len());
            header.set_mode(0o600);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            builder.append(&header, &mut file)?;
        }
        builder.finish()?;
    }
    Ok(buf)
}

fn age_encrypt_to_recipient(
    plaintext: &[u8],
    recipient: &dyn Recipient,
) -> Result<Vec<u8>, CliError> {
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient))
        .map_err(|e| CliError::Config(e.to_string()))?;
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CliError::Config(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CliError::Config(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| CliError::Config(e.to_string()))?;
    Ok(encrypted)
}

fn age_encrypt_to_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CliError> {
    let encryptor = Encryptor::with_user_passphrase(AgeSecretString::from(passphrase.to_string()));
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CliError::Config(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CliError::Config(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| CliError::Config(e.to_string()))?;
    Ok(encrypted)
}

fn age_decrypt_layer(
    ciphertext: &[u8],
    identities: &mut [Box<dyn Identity>],
) -> Result<Vec<u8>, CliError> {
    let decryptor =
        Decryptor::new_buffered(ciphertext).map_err(|e| CliError::Config(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))
        .map_err(|e| CliError::Config(e.to_string()))?;
    let mut plain = Vec::new();
    reader.read_to_end(&mut plain)?;
    Ok(plain)
}

/// Outer layer: sync host passphrase (scrypt). Inner layer: sync X25519 public key.
fn encrypt_host_archive(
    plaintext: &[u8],
    host_passphrase: &str,
    recipient: &age::x25519::Recipient,
) -> Result<Vec<u8>, CliError> {
    let inner = age_encrypt_to_recipient(plaintext, recipient)?;
    age_encrypt_to_passphrase(&inner, host_passphrase)
}

fn decrypt_host_archive(
    ciphertext: &[u8],
    host_passphrase: &str,
    identity: &age::x25519::Identity,
) -> Result<Vec<u8>, CliError> {
    let mut pass_identity: Box<dyn Identity> = Box::new(age::scrypt::Identity::new(
        AgeSecretString::from(host_passphrase.to_string()),
    ));
    let middle = age_decrypt_layer(ciphertext, std::slice::from_mut(&mut pass_identity))?;
    let mut key_identity: Box<dyn Identity> = Box::new(identity.clone());
    age_decrypt_layer(&middle, std::slice::from_mut(&mut key_identity))
}

fn extract_tar(plain: &[u8], vault_root: &Path) -> Result<(), CliError> {
    let mut archive = tar::Archive::new(plain);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.to_string_lossy().contains("..") {
            return Err(CliError::Config("invalid path in snapshot archive".into()));
        }
        let out = vault_root.join(path);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        entry.unpack(&out)?;
    }
    Ok(())
}

fn vault_has_overwritable_files(layout: &VaultLayout) -> bool {
    layout.config_file.is_file()
        || layout.passwords.is_file()
        || layout.totp.is_file()
        || layout.backup.is_file()
}

pub fn snapshot_export(config: &Config, snapshot_root: &Path) -> Result<(), CliError> {
    lifecycle::backup(config)?;
    let layout = VaultLayout::from_config(config);
    let identity = ensure_snapshot_identity(snapshot_root)?;
    let recipient = identity.to_public();
    let (host_path, pub_path) = host_paths(config, snapshot_root);

    let host_passphrase =
        rpassword::prompt_password("Sync host passphrase: ").map_err(CliError::Io)?;

    let entries = collect_vault_files(&layout, config)?;
    let tar = build_tar(&entries)?;
    let encrypted = encrypt_host_archive(&tar, &host_passphrase, &recipient)?;

    fs::create_dir_all(snapshot_root)?;
    fs::write(&host_path, encrypted)?;
    fs::write(&pub_path, recipient.to_string())?;
    set_private_file_permissions(&host_path)?;
    println!(
        "Exported snapshot to {} (local identity: {})",
        host_path.display(),
        snapshot_identity_path(snapshot_root).display()
    );
    Ok(())
}

pub fn snapshot_import(config: &Config, snapshot_root: &Path) -> Result<(), CliError> {
    materialize_snapshot(config, snapshot_root, None)?;
    let config = crate::config::load_config()?;
    let layout = VaultLayout::from_config(&config);
    println!("Import complete into {}", layout.root.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_snapshot_identity_creates_traversable_sync_dir() {
        let dir = std::env::temp_dir().join(format!("nvlt-snap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let identity = ensure_snapshot_identity(&dir).unwrap();
        let sync_dir = dir.join(".nvlt-sync");
        let id_path = sync_dir.join(SYNC_IDENTITY_FILE);
        assert!(id_path.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sync_dir, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let reloaded = ensure_snapshot_identity(&dir).unwrap();
        assert_eq!(
            reloaded.to_public().to_string(),
            identity.to_public().to_string()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&sync_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            let file_mode = fs::metadata(&id_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_archive_round_trip() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let plain = b"hello-snapshot-payload";
        let enc = encrypt_host_archive(plain, "sync-pass", &recipient).unwrap();
        let dec = decrypt_host_archive(&enc, "sync-pass", &identity).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn build_tar_round_trip() {
        let dir = std::env::temp_dir().join(format!("nvlt-tar-rt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        fs::write(&cfg, "[vault]\nlock = \"x\"\n").unwrap();

        let tar = build_tar(&[(VAULT_CONFIG_FILE.to_string(), cfg.clone())]).unwrap();
        let out_root = dir.join("extract");
        extract_tar(&tar, &out_root).unwrap();
        assert_eq!(
            fs::read_to_string(out_root.join(VAULT_CONFIG_FILE)).unwrap(),
            fs::read_to_string(&cfg).unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tar_append_without_cksum_fails_extract() {
        let mut buf = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            let mut header = Header::new_gnu();
            header.set_path("config.toml").unwrap();
            header.set_size(1);
            header.set_mode(0o600);
            header.set_entry_type(EntryType::Regular);
            builder.append(&header, &mut &b"x"[..]).unwrap();
            builder.finish().unwrap();
        }
        let err = extract_tar(&buf, Path::new("/tmp/unused")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cksum") || msg.contains("checksum"),
            "expected tar checksum error, got: {msg}"
        );
    }

    #[test]
    fn snapshot_tar_through_host_archive_round_trip() {
        let dir = std::env::temp_dir().join(format!("nvlt-snap-full-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        fs::write(&cfg, "[vault]\nlock = \"test-lock\"\n").unwrap();

        let tar = build_tar(&[(VAULT_CONFIG_FILE.to_string(), cfg.clone())]).unwrap();
        let identity = age::x25519::Identity::generate();
        let enc = encrypt_host_archive(&tar, "sync-pass", &identity.to_public()).unwrap();
        let plain = decrypt_host_archive(&enc, "sync-pass", &identity).unwrap();
        let out_root = dir.join("extract");
        extract_tar(&plain, &out_root).unwrap();
        assert_eq!(
            fs::read_to_string(out_root.join(VAULT_CONFIG_FILE)).unwrap(),
            fs::read_to_string(&cfg).unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
