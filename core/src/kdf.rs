use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use crate::error::Error;
use crate::secrets::composite_passphrase;

/// Argon2id cost parameters (defaults match vault-config spec).
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Memory cost in KiB (65536 = 64 MiB).
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost_kib: 65536,
            time_cost: 3,
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

/// Derive a 32-byte key and return it hex-encoded in a `SecretString`.
pub fn derive_key(
    password: &SecretString,
    seed: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    let composite = composite_passphrase(password, seed);
    let mut material = composite.expose_secret().clone();
    let result = derive_key_from_material(&material, salt, params);
    material.zeroize();
    result
}

/// Derive a wrap key from master password only (for `nvlt.enc` seed blobs).
pub fn derive_wrap_key(
    password: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    let mut material = password.expose_secret().clone();
    let result = derive_key_from_material(&material, salt, params);
    material.zeroize();
    result
}

fn derive_key_from_material(
    material: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    let argon_params = params.to_argon2_params()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon_params);

    let salt_string = SaltString::encode_b64(salt).map_err(|_| Error::Kdf)?;
    let hash = argon2
        .hash_password(material.as_bytes(), &salt_string)
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

/// Generate a random 16-byte salt suitable for `salt.bin` (used by vault init in a later change).
#[allow(dead_code)]
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn sample_salt() -> [u8; 16] {
        *b"vault-test-salt!"
    }

    #[test]
    fn kdf_is_deterministic() {
        let password = SecretString::new("master-password".to_string());
        let seed = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string());
        let params = KdfParams::fast_test();
        let salt = sample_salt();

        let a = derive_key(&password, &seed, &salt, params).unwrap();
        let b = derive_key(&password, &seed, &salt, params).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn kdf_differs_when_password_or_seed_changes() {
        let password_a = SecretString::new("password-a".to_string());
        let password_b = SecretString::new("password-b".to_string());
        let seed_a = SecretString::new("JBSWY3DPEHPK3PXP".to_string());
        let seed_b = SecretString::new("KRSXG5CTMVRXEZLU".to_string());
        let params = KdfParams::fast_test();
        let salt = sample_salt();

        let key_aa = derive_key(&password_a, &seed_a, &salt, params).unwrap();
        let key_ab = derive_key(&password_a, &seed_b, &salt, params).unwrap();
        let key_ba = derive_key(&password_b, &seed_a, &salt, params).unwrap();

        assert_ne!(key_aa.expose_secret(), key_ab.expose_secret());
        assert_ne!(key_aa.expose_secret(), key_ba.expose_secret());
    }
}
