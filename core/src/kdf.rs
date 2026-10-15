use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::Error;

/// Argon2id cost parameters (defaults match vault-config spec).
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Memory cost in KiB (262144 = 256 MiB).
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost_kib: 262144,
            time_cost: 4,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    pub fn to_argon2_params(&self) -> Result<Params, Error> {
        Params::new(
            self.memory_cost_kib,
            self.time_cost,
            self.parallelism,
            Some(32),
        )
        .map_err(|_| Error::Kdf)
    }

    /// Reduced costs for unit tests only.
    #[cfg(test)]
    pub fn fast_test() -> Self {
        Self {
            memory_cost_kib: 256,
            time_cost: 1,
            parallelism: 1,
        }
    }
}

/// Derive the vault data key through the v2 KDF chain.
///
/// The key layer is hardened first (`key_secret` + salt), then the password
/// layer is applied over its output, so both the master password and the
/// private key file are required.
pub fn derive_key(
    password: &SecretString,
    key_secret: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    let key_layer = derive_key_from_material(key_secret, salt, params)?;

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(key_layer.expose_secret().as_bytes());
    let digest = hasher.finalize();

    derive_key_from_material(password, &digest[..16], params)
}

fn derive_key_from_material(
    material: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    let argon_params = params.to_argon2_params()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon_params);

    let salt_string = SaltString::encode_b64(salt).map_err(|_| Error::Kdf)?;
    let hash = argon2
        .hash_password(material.expose_secret().as_bytes(), &salt_string)
        .map_err(|_| Error::Kdf)?;

    let hash_bytes = hash.hash.ok_or(Error::Kdf)?;
    let key_bytes = hash_bytes.as_bytes();
    if key_bytes.len() != 32 {
        return Err(Error::Kdf);
    }

    let mut hex_key = hex::encode(key_bytes);
    let secret = SecretString::new(hex_key.clone());
    hex_key.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn sample_salt() -> [u8; 16] {
        *b"vault-test-salt!"
    }

    fn key_secret() -> SecretString {
        SecretString::new("AGE-SECRET-KEY-1TESTSECRET".to_string())
    }

    #[test]
    fn kdf_is_deterministic() {
        let password = SecretString::new("master-password".to_string());
        let params = KdfParams::fast_test();
        let salt = sample_salt();

        let a = derive_key(&password, &key_secret(), &salt, params).unwrap();
        let b = derive_key(&password, &key_secret(), &salt, params).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn kdf_differs_when_password_or_key_changes() {
        let password_a = SecretString::new("password-a".to_string());
        let password_b = SecretString::new("password-b".to_string());
        let key_a = SecretString::new("AGE-SECRET-KEY-1AAAA".to_string());
        let key_b = SecretString::new("AGE-SECRET-KEY-1BBBB".to_string());
        let params = KdfParams::fast_test();
        let salt = sample_salt();

        let key_aa = derive_key(&password_a, &key_a, &salt, params).unwrap();
        let key_ab = derive_key(&password_a, &key_b, &salt, params).unwrap();
        let key_ba = derive_key(&password_b, &key_a, &salt, params).unwrap();

        assert_ne!(key_aa.expose_secret(), key_ab.expose_secret());
        assert_ne!(key_aa.expose_secret(), key_ba.expose_secret());
    }
}
