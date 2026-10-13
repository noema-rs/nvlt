use std::path::Path;

use chrono::Utc;
use secrecy::SecretString;
use vault_core::{decrypt, encrypt};

use crate::confirm::{remove_confirmation, RemoveConfirmation};
use crate::error::Error;
use crate::model::{NewTotpEntry, TotpDocument, TotpEntry, TOTP_STORE_VERSION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpStore {
    document: TotpDocument,
}

impl TotpStore {
    pub fn empty() -> Self {
        Self::from_document(TotpDocument::empty())
    }

    pub fn from_document(document: TotpDocument) -> Self {
        Self { document }
    }

    pub fn load_encrypted(key: &SecretString, ciphertext: &[u8]) -> Result<Self, Error> {
        let plaintext = decrypt(key, ciphertext)?;
        let document: TotpDocument = serde_json::from_slice(&plaintext)?;
        if document.version != TOTP_STORE_VERSION {
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

    pub fn document(&self) -> &TotpDocument {
        &self.document
    }

    pub fn list(&self) -> impl Iterator<Item = &TotpEntry> {
        self.document.entries.iter()
    }

    pub fn get(&self, site: &str) -> Result<&TotpEntry, Error> {
        self.find_index(site).map(|idx| &self.document.entries[idx])
    }

    pub fn add(&mut self, entry: NewTotpEntry) -> Result<(), Error> {
        if self.find_index(&entry.site).is_ok() {
            return Err(Error::Duplicate { site: entry.site });
        }
        self.document.entries.push(entry.into_entry(Utc::now()));
        Ok(())
    }

    pub fn prepare_remove(&self, site: &str) -> Result<RemoveConfirmation, Error> {
        self.get(site)?;
        Ok(remove_confirmation(site))
    }

    pub fn remove(&mut self, site: &str) -> Result<(), Error> {
        let idx = self.find_index(site)?;
        self.document.entries.remove(idx);
        Ok(())
    }

    pub fn export_uri_to_path(&self, site: &str, path: impl AsRef<Path>) -> Result<(), Error> {
        let uri = self.get(site)?.otpauth_uri()?;
        std::fs::write(path, uri)?;
        Ok(())
    }

    /// Writes a PNG QR code when the path ends in `.png`; otherwise writes the otpauth URI as text.
    pub fn export_to_path(&self, site: &str, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        let uri = self.get(site)?.otpauth_uri()?;
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("png"))
        {
            crate::qr::write_qr_png(&uri, path)
        } else {
            std::fs::write(path, uri)?;
            Ok(())
        }
    }

    pub fn import_uri_from_path(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        let uri = std::fs::read_to_string(path)?;
        let entry = crate::model::parse_otpauth_uri(uri.trim())?;
        self.add(entry)
    }

    /// Imports from a QR image (png/jpeg/…) or a text file containing an otpauth URI.
    pub fn import_from_path(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        if crate::qr::is_image_path(path) {
            let uri = crate::qr::read_uri_from_image(path)?;
            let entry = crate::model::parse_otpauth_uri(uri.trim())?;
            self.add(entry)
        } else {
            self.import_uri_from_path(path)
        }
    }

    fn find_index(&self, site: &str) -> Result<usize, Error> {
        self.document
            .entries
            .iter()
            .position(|e| e.site == site)
            .ok_or_else(|| Error::NotFound {
                site: site.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::default_entry;
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
    fn crud_round_trip() {
        let key = test_key();
        let mut store = TotpStore::empty();
        store
            .add(default_entry(
                "solo-2fa.com",
                "user",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            ))
            .unwrap();

        let blob = store.save_encrypted(&key).unwrap();
        let loaded = TotpStore::load_encrypted(&key, &blob).unwrap();
        let entry = loaded.get("solo-2fa.com").unwrap();
        assert!(entry.current_code().unwrap().code.len() >= 6);
    }
}
