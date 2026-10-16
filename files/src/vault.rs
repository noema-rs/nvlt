use std::path::{Path, PathBuf};

use secrecy::SecretString;
use vault_core::{decrypt, encrypt};

use crate::error::Error;

/// Whether an encrypt operation may replace an existing stored name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePolicy {
    RefuseIfExists,
    Allow,
}

#[derive(Debug, Clone)]
pub struct FileVault {
    dir: PathBuf,
}

impl FileVault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn stored_path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn list(&self) -> Result<Vec<String>, Error> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn encrypt_file(
        &self,
        source: impl AsRef<Path>,
        key: &SecretString,
        overwrite: OverwritePolicy,
    ) -> Result<String, Error> {
        let source = source.as_ref();
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::InvalidSourcePath)?
            .to_string();
        self.encrypt_file_as(source, &name, key, overwrite)
    }

    pub fn encrypt_file_as(
        &self,
        source: impl AsRef<Path>,
        vault_name: &str,
        key: &SecretString,
        overwrite: OverwritePolicy,
    ) -> Result<String, Error> {
        let source = source.as_ref();
        if vault_name.is_empty() || vault_name.contains('/') || vault_name.contains('\\') {
            return Err(Error::InvalidVaultName);
        }
        let name = vault_name.to_string();
        let dest = self.stored_path(&name);
        if dest.exists() && overwrite == OverwritePolicy::RefuseIfExists {
            return Err(Error::AlreadyExists { name });
        }
        let plaintext = std::fs::read(source)?;
        let ciphertext = encrypt(key, &plaintext)?;
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(dest, ciphertext)?;
        Ok(name)
    }

    pub fn decrypt_to_path(
        &self,
        name: &str,
        dest: impl AsRef<Path>,
        key: &SecretString,
    ) -> Result<(), Error> {
        let plaintext = self.decrypt_bytes(name, key)?;
        std::fs::write(dest, plaintext)?;
        Ok(())
    }

    pub fn decrypt_stdout(&self, name: &str, key: &SecretString) -> Result<Vec<u8>, Error> {
        self.decrypt_bytes(name, key)
    }

    pub fn remove(&self, name: &str) -> Result<(), Error> {
        let path = self.stored_path(name);
        if !path.is_file() {
            return Err(Error::NotFound {
                name: name.to_string(),
            });
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    fn decrypt_bytes(&self, name: &str, key: &SecretString) -> Result<Vec<u8>, Error> {
        let path = self.stored_path(name);
        if !path.is_file() {
            return Err(Error::NotFound {
                name: name.to_string(),
            });
        }
        let ciphertext = std::fs::read(path)?;
        decrypt(key, &ciphertext).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::KdfParams;

    fn test_key() -> SecretString {
        vault_core::derive_key(
            &SecretString::new("password".to_string()),
            &SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()),
            b"vault-test-salt!",
            KdfParams {
                memory_cost_kib: 256,
                time_cost: 1,
                parallelism: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn round_trip_small_file() {
        let base = std::env::temp_dir().join(format!("vault-files-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let source = base.join("note.txt");
        std::fs::write(&source, b"hello vault").unwrap();

        let vault = FileVault::new(base.join("store"));
        let key = test_key();
        let name = vault
            .encrypt_file(&source, &key, OverwritePolicy::RefuseIfExists)
            .unwrap();
        assert_eq!(name, "note.txt");

        let out = vault.decrypt_stdout(&name, &key).unwrap();
        assert_eq!(out, b"hello vault");

        let _ = std::fs::remove_dir_all(&base);
    }
}
