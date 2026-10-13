use std::path::{Path, PathBuf};

use secrecy::SecretString;
use vault_core::{decrypt, encrypt};

use crate::confirm::{
    remove_profile_confirmation, unset_confirmation, RemoveProfileConfirmation, UnsetConfirmation,
};
use crate::error::Error;
use crate::model::{export_line, EnvProfileDocument, EnvVar, ENV_PROFILE_VERSION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileStore {
    document: EnvProfileDocument,
}

impl ProfileStore {
    pub fn empty(profile: impl Into<String>) -> Self {
        Self::from_document(EnvProfileDocument::empty(profile))
    }

    pub fn from_document(document: EnvProfileDocument) -> Self {
        Self { document }
    }

    pub fn profile_name(&self) -> &str {
        &self.document.profile
    }

    pub fn document(&self) -> &EnvProfileDocument {
        &self.document
    }

    pub fn load_encrypted(key: &SecretString, ciphertext: &[u8]) -> Result<Self, Error> {
        let plaintext = decrypt(key, ciphertext)?;
        let document: EnvProfileDocument = serde_json::from_slice(&plaintext)?;
        if document.version != ENV_PROFILE_VERSION {
            return Err(Error::InvalidFile);
        }
        Ok(Self { document })
    }

    pub fn save_encrypted(&self, key: &SecretString) -> Result<Vec<u8>, Error> {
        let plaintext = serde_json::to_vec(&self.document)?;
        encrypt(key, &plaintext).map_err(Error::from)
    }

    pub fn load_path(key: &SecretString, path: impl AsRef<Path>) -> Result<Self, Error> {
        let ciphertext = std::fs::read(path)?;
        Self::load_encrypted(key, &ciphertext)
    }

    pub fn save_path(&self, key: &SecretString, path: impl AsRef<Path>) -> Result<(), Error> {
        let ciphertext = self.save_encrypted(key)?;
        std::fs::write(path, ciphertext)?;
        Ok(())
    }

    pub fn list_keys(&self) -> impl Iterator<Item = &str> {
        self.document.vars.iter().map(|v| v.key.as_str())
    }

    pub fn get(&self, key: &str) -> Result<&str, Error> {
        self.document
            .vars
            .iter()
            .find(|v| v.key == key)
            .map(|v| v.value.as_str())
            .ok_or_else(|| Error::VarNotFound {
                profile: self.document.profile.clone(),
                key: key.to_string(),
            })
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(var) = self.document.vars.iter_mut().find(|v| v.key == key) {
            var.value = value;
        } else {
            self.document.vars.push(EnvVar { key, value });
        }
    }

    pub fn prepare_unset(&self, key: &str) -> Result<UnsetConfirmation, Error> {
        self.get(key)?;
        Ok(unset_confirmation(self.profile_name(), key))
    }

    pub fn unset(&mut self, key: &str) -> Result<(), Error> {
        let idx = self
            .document
            .vars
            .iter()
            .position(|v| v.key == key)
            .ok_or_else(|| Error::VarNotFound {
                profile: self.document.profile.clone(),
                key: key.to_string(),
            })?;
        self.document.vars.remove(idx);
        Ok(())
    }

    pub fn export_lines(&self) -> Vec<String> {
        self.document
            .vars
            .iter()
            .map(|v| export_line(&v.key, &v.value))
            .collect()
    }
}

/// Directory-backed collection of profile files (`<name>.age`).
#[derive(Debug, Clone)]
pub struct EnvVault {
    dir: PathBuf,
}

impl EnvVault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn profile_path(&self, profile: &str) -> PathBuf {
        self.dir.join(format!("{profile}.age"))
    }

    pub fn list_profiles(&self) -> Result<Vec<String>, Error> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "age") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn load_profile(&self, profile: &str, key: &SecretString) -> Result<ProfileStore, Error> {
        let path = self.profile_path(profile);
        if !path.is_file() {
            return Err(Error::ProfileNotFound {
                profile: profile.to_string(),
            });
        }
        ProfileStore::load_path(key, path)
    }

    pub fn save_profile(&self, store: &ProfileStore, key: &SecretString) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir)?;
        store.save_path(key, self.profile_path(store.profile_name()))
    }

    pub fn add_profile(&self, profile: &str, key: &SecretString) -> Result<(), Error> {
        let path = self.profile_path(profile);
        if path.exists() {
            return Err(Error::ProfileExists {
                profile: profile.to_string(),
            });
        }
        std::fs::create_dir_all(&self.dir)?;
        ProfileStore::empty(profile).save_path(key, path)
    }

    pub fn prepare_remove_profile(
        &self,
        profile: &str,
    ) -> Result<RemoveProfileConfirmation, Error> {
        let path = self.profile_path(profile);
        if !path.is_file() {
            return Err(Error::ProfileNotFound {
                profile: profile.to_string(),
            });
        }
        Ok(remove_profile_confirmation(profile))
    }

    pub fn remove_profile(&self, profile: &str) -> Result<(), Error> {
        let path = self.profile_path(profile);
        if !path.is_file() {
            return Err(Error::ProfileNotFound {
                profile: profile.to_string(),
            });
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    /// Load or create a profile, apply `set`, and persist.
    pub fn set_var(
        &self,
        profile: &str,
        var_key: &str,
        value: &str,
        key: &SecretString,
    ) -> Result<(), Error> {
        let mut store = match self.load_profile(profile, key) {
            Ok(s) => s,
            Err(Error::ProfileNotFound { .. }) => ProfileStore::empty(profile),
            Err(e) => return Err(e),
        };
        store.set(var_key, value);
        self.save_profile(&store, key)
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
    fn profile_lifecycle_and_export() {
        let dir = std::env::temp_dir().join(format!("vault-envs-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = EnvVault::new(&dir);
        let key = test_key();

        vault.add_profile("proyecto-x", &key).unwrap();
        vault
            .set_var("proyecto-x", "API_KEY", "sk-abc", &key)
            .unwrap();

        let store = vault.load_profile("proyecto-x", &key).unwrap();
        assert_eq!(store.get("API_KEY").unwrap(), "sk-abc");
        let lines = store.export_lines();
        assert_eq!(lines, vec![r#"export API_KEY="sk-abc""#.to_string()]);

        store.prepare_unset("API_KEY").unwrap();
        let mut store = vault.load_profile("proyecto-x", &key).unwrap();
        store.unset("API_KEY").unwrap();
        vault.save_profile(&store, &key).unwrap();

        vault.prepare_remove_profile("proyecto-x").unwrap();
        vault.remove_profile("proyecto-x").unwrap();
        assert!(vault.list_profiles().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
