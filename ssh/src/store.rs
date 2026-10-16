use std::path::Path;

use chrono::Utc;
use secrecy::SecretString;
use vault_core::{decrypt, encrypt};

use crate::error::Error;
use crate::model::{NewSshEntry, SshDocument, SshEntry, SSH_STORE_VERSION};

pub struct SshStore {
    document: SshDocument,
}

impl SshStore {
    pub fn empty() -> Self {
        Self::from_document(SshDocument::empty())
    }

    pub fn from_document(document: SshDocument) -> Self {
        Self { document }
    }

    pub fn load_path(key: &SecretString, path: impl AsRef<Path>) -> Result<Self, Error> {
        let ciphertext = std::fs::read(path)?;
        Self::load_encrypted(key, &ciphertext)
    }

    pub fn load_encrypted(key: &SecretString, ciphertext: &[u8]) -> Result<Self, Error> {
        let plain = decrypt(key, ciphertext)?;
        let document: SshDocument = serde_json::from_slice(&plain)?;
        if document.version != SSH_STORE_VERSION {
            return Err(Error::InvalidFile);
        }
        Ok(Self { document })
    }

    pub fn save_path(&self, key: &SecretString, path: impl AsRef<Path>) -> Result<(), Error> {
        let ciphertext = self.save_encrypted(key)?;
        std::fs::write(path, ciphertext)?;
        Ok(())
    }

    pub fn save_encrypted(&self, key: &SecretString) -> Result<Vec<u8>, Error> {
        let plain = serde_json::to_vec(&self.document)?;
        encrypt(key, &plain).map_err(Error::from)
    }

    pub fn list(&self) -> impl Iterator<Item = &SshEntry> {
        self.document.entries.iter()
    }

    pub fn get_mut(&mut self, name: &str) -> Result<&mut SshEntry, Error> {
        let idx = self
            .document
            .entries
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| Error::NotFound {
                name: name.to_string(),
            })?;
        Ok(&mut self.document.entries[idx])
    }

    pub fn add(&mut self, entry: NewSshEntry) -> Result<(), Error> {
        if self.document.entries.iter().any(|e| e.name == entry.name) {
            return Err(Error::Duplicate {
                name: entry.name.clone(),
            });
        }
        self.document.entries.push(entry.into_entry(Utc::now()));
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<SshEntry, Error> {
        let idx = self
            .document
            .entries
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| Error::NotFound {
                name: name.to_string(),
            })?;
        Ok(self.document.entries.remove(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_name_rejected() {
        let mut store = SshStore::empty();
        let entry = NewSshEntry {
            name: "a".into(),
            private_pem: "priv".into(),
            public_openssh: Some("pub".into()),
            host: None,
            user: None,
        };
        store.add(entry.clone()).unwrap();
        assert!(matches!(store.add(entry), Err(Error::Duplicate { .. })));
    }

    #[test]
    fn private_only_entry_has_no_public_key() {
        let mut store = SshStore::empty();
        store
            .add(NewSshEntry {
                name: "solo".into(),
                private_pem: "priv".into(),
                public_openssh: None,
                host: None,
                user: None,
            })
            .unwrap();
        assert!(store.list().next().unwrap().public_openssh.is_none());
    }
}
