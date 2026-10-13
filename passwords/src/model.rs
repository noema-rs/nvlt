use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::Error;

pub const PASSWORDS_FILE_VERSION: u32 = 2;

/// On-disk JSON document inside encrypted `pass.age`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordsDocument {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl PasswordsDocument {
    pub fn empty() -> Self {
        Self {
            version: PASSWORDS_FILE_VERSION,
            entries: Vec::new(),
        }
    }
}

/// A single credential row; unique key is `(domain, username)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub domain: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<EmbeddedTotp>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<ExtraField>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// TOTP parameters stored alongside a password entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedTotp {
    pub seed: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    fn to_totp_rs(self) -> Algorithm {
        match self {
            TotpAlgorithm::Sha1 => Algorithm::SHA1,
            TotpAlgorithm::Sha256 => Algorithm::SHA256,
            TotpAlgorithm::Sha512 => Algorithm::SHA512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraField {
    pub key: String,
    pub value: String,
}

/// Current TOTP code and seconds remaining for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
}

impl Entry {
    /// Generate the current embedded TOTP code if configured.
    pub fn current_totp(&self) -> Result<Option<TotpCode>, Error> {
        let Some(cfg) = &self.totp else {
            return Ok(None);
        };
        let code = cfg.generate_current()?;
        Ok(Some(code))
    }
}

impl EmbeddedTotp {
    fn build_totp(&self) -> Result<TOTP, Error> {
        let secret = Secret::Encoded(self.seed.clone())
            .to_bytes()
            .map_err(|_| vault_core::Error::InvalidTotpSeed)?;

        TOTP::new(
            self.algorithm.to_totp_rs(),
            usize::from(self.digits),
            0,
            u64::from(self.period),
            secret,
            None,
            "vault".to_string(),
        )
        .map_err(|_| vault_core::Error::InvalidTotpSeed)
        .map_err(Error::from)
    }

    fn generate_current(&self) -> Result<TotpCode, Error> {
        let totp = self.build_totp()?;
        let code = totp
            .generate_current()
            .map_err(|_| vault_core::Error::TotpGenerate)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| vault_core::Error::TotpGenerate)?
            .as_secs();
        let period = u64::from(self.period);
        let seconds_remaining = period - (now % period);
        Ok(TotpCode {
            code,
            seconds_remaining,
        })
    }
}

/// Fields supplied when creating a new entry (timestamps are set by the store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEntry {
    pub domain: String,
    pub username: String,
    pub password: String,
    pub totp: Option<EmbeddedTotp>,
    pub notes: String,
    pub fields: Vec<ExtraField>,
}

/// Replacement payload for [`PasswordStore::edit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryUpdate {
    pub password: String,
    pub totp: Option<EmbeddedTotp>,
    pub notes: String,
    pub fields: Vec<ExtraField>,
}

impl NewEntry {
    pub fn into_entry(self, now: DateTime<Utc>) -> Entry {
        Entry {
            domain: self.domain,
            username: self.username,
            password: self.password,
            totp: self.totp,
            notes: self.notes,
            fields: self.fields,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Default embedded TOTP parameters matching common issuers.
pub fn default_embedded_totp(seed: impl Into<String>) -> EmbeddedTotp {
    EmbeddedTotp {
        seed: seed.into(),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_round_trip_json() {
        let doc = PasswordsDocument {
            version: 2,
            entries: vec![Entry {
                domain: "github.com".into(),
                username: "u@example.com".into(),
                password: "secret".into(),
                totp: Some(default_embedded_totp("JBSWY3DPEHPK3PXP")),
                notes: String::new(),
                fields: vec![ExtraField {
                    key: "PIN".into(),
                    value: "1234".into(),
                }],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
        };
        let json = serde_json::to_string(&doc).unwrap();
        let back: PasswordsDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, back);
    }
}
