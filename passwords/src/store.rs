use std::path::Path;

use chrono::Utc;
use secrecy::SecretString;
use vault_core::{decrypt, encrypt};

use crate::confirm::{
    edit_confirmation, remove_confirmation, EditConfirmation, RemoveConfirmation,
};
use crate::error::Error;
use crate::model::{Entry, EntryUpdate, NewEntry, PasswordsDocument};

/// In-memory password vault backed by encrypted `pass.age`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordStore {
    document: PasswordsDocument,
}

impl PasswordStore {
    pub fn empty() -> Self {
        Self::from_document(PasswordsDocument::empty())
    }

    pub fn from_document(document: PasswordsDocument) -> Self {
        Self { document }
    }

    pub fn document(&self) -> &PasswordsDocument {
        &self.document
    }

    pub fn load_encrypted(key: &SecretString, ciphertext: &[u8]) -> Result<Self, Error> {
        let plaintext = decrypt(key, ciphertext)?;
        let document: PasswordsDocument = serde_json::from_slice(&plaintext)?;
        if document.version != crate::model::PASSWORDS_FILE_VERSION {
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

    pub fn list(&self) -> impl Iterator<Item = &Entry> {
        self.document.entries.iter()
    }

    pub fn search_domain(&self, domain: &str) -> Vec<&Entry> {
        self.document
            .entries
            .iter()
            .filter(|e| e.domain == domain)
            .collect()
    }

    pub fn search(&self, domain: &str, username: Option<&str>) -> Vec<&Entry> {
        match username {
            Some(user) => self
                .document
                .entries
                .iter()
                .filter(|e| e.domain == domain && e.username == user)
                .collect(),
            None => self.search_domain(domain),
        }
    }

    pub fn get(&self, domain: &str, username: &str) -> Result<&Entry, Error> {
        self.find_index(domain, username)
            .map(|idx| &self.document.entries[idx])
    }

    pub fn add(&mut self, entry: NewEntry) -> Result<(), Error> {
        if self.find_index(&entry.domain, &entry.username).is_ok() {
            return Err(Error::Duplicate {
                domain: entry.domain,
                username: entry.username,
            });
        }
        let now = Utc::now();
        self.document.entries.push(entry.into_entry(now));
        Ok(())
    }

    pub fn prepare_edit(&self, domain: &str, username: &str) -> Result<EditConfirmation, Error> {
        self.get(domain, username)?;
        Ok(edit_confirmation(domain, username))
    }

    pub fn edit(&mut self, domain: &str, username: &str, update: EntryUpdate) -> Result<(), Error> {
        let idx = self.find_index(domain, username)?;
        let entry = &mut self.document.entries[idx];
        entry.password = update.password;
        entry.totp = update.totp;
        entry.notes = update.notes;
        entry.fields = update.fields;
        entry.updated_at = Utc::now();
        Ok(())
    }

    pub fn prepare_remove(
        &self,
        domain: &str,
        username: &str,
    ) -> Result<RemoveConfirmation, Error> {
        self.get(domain, username)?;
        Ok(remove_confirmation(domain, username))
    }

    pub fn remove(&mut self, domain: &str, username: &str) -> Result<(), Error> {
        let idx = self.find_index(domain, username)?;
        self.document.entries.remove(idx);
        Ok(())
    }

    fn find_index(&self, domain: &str, username: &str) -> Result<usize, Error> {
        self.document
            .entries
            .iter()
            .position(|e| e.domain == domain && e.username == username)
            .ok_or_else(|| Error::NotFound {
                domain: domain.to_string(),
                username: username.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::default_embedded_totp;
    use vault_core::KdfParams;

    fn test_key() -> SecretString {
        let password = SecretString::new("password".to_string());
        let seed = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string());
        vault_core::derive_key(
            &password,
            &seed,
            b"vault-test-salt!",
            KdfParams {
                memory_cost_kib: 256,
                time_cost: 1,
                parallelism: 1,
            },
        )
        .unwrap()
    }

    fn sample_new(domain: &str, user: &str) -> NewEntry {
        NewEntry {
            domain: domain.into(),
            username: user.into(),
            password: "hunter2".into(),
            totp: None,
            notes: String::new(),
            fields: vec![],
        }
    }

    #[test]
    fn save_load_round_trip() {
        let key = test_key();
        let mut store = PasswordStore::empty();
        store.add(sample_new("github.com", "a@x.com")).unwrap();

        let blob = store.save_encrypted(&key).unwrap();
        let loaded = PasswordStore::load_encrypted(&key, &blob).unwrap();
        assert_eq!(loaded.list().count(), 1);
        assert_eq!(
            loaded.get("github.com", "a@x.com").unwrap().password,
            "hunter2"
        );
    }

    #[test]
    fn duplicate_add_fails() {
        let mut store = PasswordStore::empty();
        store.add(sample_new("d.com", "u")).unwrap();
        let err = store.add(sample_new("d.com", "u")).unwrap_err();
        assert!(matches!(err, Error::Duplicate { .. }));
    }

    #[test]
    fn not_found_on_get_and_remove() {
        let store = PasswordStore::empty();
        assert!(matches!(
            store.get("missing.com", "nope").unwrap_err(),
            Error::NotFound { .. }
        ));
        let mut store = PasswordStore::empty();
        assert!(matches!(
            store.remove("missing.com", "nope").unwrap_err(),
            Error::NotFound { .. }
        ));
    }

    #[test]
    fn search_and_edit() {
        let mut store = PasswordStore::empty();
        store.add(sample_new("github.com", "a@x.com")).unwrap();
        store.add(sample_new("github.com", "b@x.com")).unwrap();
        assert_eq!(store.search_domain("github.com").len(), 2);
        assert_eq!(store.search("github.com", Some("a@x.com")).len(), 1);

        store
            .edit(
                "github.com",
                "a@x.com",
                EntryUpdate {
                    password: "new".into(),
                    totp: Some(default_embedded_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
                    notes: "note".into(),
                    fields: vec![],
                },
            )
            .unwrap();
        let entry = store.get("github.com", "a@x.com").unwrap();
        assert_eq!(entry.password, "new");
        assert!(entry.totp.is_some());
        assert!(entry.current_totp().unwrap().is_some());
    }
}
