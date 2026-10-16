use secrecy::{ExposeSecret, SecretString};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::Error;

const DEFAULT_DIGITS: usize = 6;
const DEFAULT_PERIOD: u64 = 30;

fn build_totp(seed: &SecretString) -> Result<TOTP, Error> {
    let secret = Secret::Encoded(seed.expose_secret().clone())
        .to_bytes()
        .map_err(|_| Error::InvalidTotpSeed)?;

    Ok(TOTP::new_unchecked(
        Algorithm::SHA1,
        DEFAULT_DIGITS,
        0,
        DEFAULT_PERIOD,
        secret,
        None,
        "vault".to_string(),
    ))
}

/// Verify a 6-digit code for the current time step only.
pub fn verify_totp(seed: &SecretString, code: &str) -> Result<bool, Error> {
    let totp = build_totp(seed)?;
    totp.check_current(code).map_err(|_| Error::TotpVerify)
}

/// Generate the current TOTP code.
pub fn generate_totp(seed: &SecretString) -> Result<String, Error> {
    let totp = build_totp(seed)?;
    totp.generate_current().map_err(|_| Error::TotpGenerate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    // Base32 encoding of 20-byte RFC 6238 test secret (`12345678901234567890`).
    const TEST_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn valid_totp_passes_verification() {
        let seed = SecretString::new(TEST_SEED.to_string());
        let code = generate_totp(&seed).unwrap();
        assert!(verify_totp(&seed, &code).unwrap());
    }

    #[test]
    fn invalid_totp_fails_verification() {
        let seed = SecretString::new(TEST_SEED.to_string());
        assert!(!verify_totp(&seed, "000000").unwrap());
    }
}
