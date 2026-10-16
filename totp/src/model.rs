use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::Error;

pub const TOTP_STORE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpDocument {
    pub version: u32,
    pub entries: Vec<TotpEntry>,
}

impl TotpDocument {
    pub fn empty() -> Self {
        Self {
            version: TOTP_STORE_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpEntry {
    pub site: String,
    pub account: String,
    pub seed: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
    pub created_at: DateTime<Utc>,
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

    fn from_totp_rs(algo: Algorithm) -> Self {
        match algo {
            Algorithm::SHA1 => TotpAlgorithm::Sha1,
            Algorithm::SHA256 => TotpAlgorithm::Sha256,
            Algorithm::SHA512 => TotpAlgorithm::Sha512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTotpEntry {
    pub site: String,
    pub account: String,
    pub seed: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

/// Normalize and validate a base32 seed, or parse a pasted `otpauth://` URI.
pub fn prepare_seed(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        return Ok(parse_otpauth_uri(trimmed)?.seed);
    }
    let normalized: String = trimmed
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err(vault_core::Error::InvalidTotpSeed.into());
    }
    Secret::Encoded(normalized.clone())
        .to_bytes()
        .map_err(|_| Error::Core(vault_core::Error::InvalidTotpSeed))?;
    Ok(normalized)
}

impl TotpEntry {
    pub fn current_code(&self) -> Result<TotpCode, Error> {
        let totp = self.build_totp()?;
        let code = totp
            .generate_current()
            .map_err(|_| vault_core::Error::TotpGenerate)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| vault_core::Error::TotpGenerate)?
            .as_secs();
        let period = u64::from(self.period);
        Ok(TotpCode {
            code,
            seconds_remaining: period - (now % period),
        })
    }

    pub fn otpauth_uri(&self) -> Result<String, Error> {
        Ok(self.build_totp()?.get_url())
    }

    fn build_totp(&self) -> Result<TOTP, Error> {
        let seed = prepare_seed(&self.seed)?;
        let secret = Secret::Encoded(seed)
            .to_bytes()
            .map_err(|_| vault_core::Error::InvalidTotpSeed)?;

        TOTP::new(
            self.algorithm.to_totp_rs(),
            usize::from(self.digits),
            0,
            u64::from(self.period),
            secret,
            Some(self.site.clone()),
            self.account.clone(),
        )
        .map_err(|_| vault_core::Error::InvalidTotpSeed)
        .map_err(Error::from)
    }
}

impl NewTotpEntry {
    pub fn into_entry(self, now: DateTime<Utc>) -> Result<TotpEntry, Error> {
        let seed = prepare_seed(&self.seed)?;
        let entry = TotpEntry {
            site: self.site,
            account: self.account,
            seed,
            algorithm: self.algorithm,
            digits: self.digits,
            period: self.period,
            created_at: now,
        };
        entry.build_totp()?;
        Ok(entry)
    }
}

pub fn parse_otpauth_uri(uri: &str) -> Result<NewTotpEntry, Error> {
    let totp = TOTP::from_url(uri).map_err(|_| Error::InvalidOtpAuth)?;
    let site = totp
        .issuer
        .clone()
        .unwrap_or_else(|| totp.account_name.clone());
    let account = totp.account_name;
    let seed = match Secret::Raw(totp.secret).to_encoded() {
        Secret::Encoded(s) => s,
        Secret::Raw(_) => return Err(Error::InvalidOtpAuth),
    };
    Ok(NewTotpEntry {
        site,
        account,
        seed,
        algorithm: TotpAlgorithm::from_totp_rs(totp.algorithm),
        digits: totp.digits as u8,
        period: totp.step as u32,
    })
}

pub fn default_entry(
    site: impl Into<String>,
    account: impl Into<String>,
    seed: impl Into<String>,
) -> NewTotpEntry {
    NewTotpEntry {
        site: site.into(),
        account: account.into(),
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
    fn prepare_seed_normalizes_base32() {
        let normalized = prepare_seed("gezd gnbv gy3t qojq gezdgnbvg y3tqojq").unwrap();
        assert_eq!(normalized, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn prepare_seed_rejects_garbage() {
        assert!(prepare_seed("not-a-valid-seed!!!").is_err());
    }
}
