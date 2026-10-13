//! Public API surface for the core crate.

use secrecy::SecretString;

use crate::crypto;
use crate::error::Error;
use crate::kdf::{self, KdfParams};
use crate::totp;

/// Derive the vault data key from master password, TOTP seed, and salt.
pub fn derive_key(
    password: &SecretString,
    seed: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    kdf::derive_key(password, seed, salt, params)
}

/// Derive a key from master password only (local seed wrap).
pub fn derive_wrap_key(
    password: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    kdf::derive_wrap_key(password, salt, params)
}

/// Encrypt plaintext with age using a derived key.
pub fn encrypt(key: &SecretString, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    crypto::encrypt(key, plaintext)
}

/// Decrypt ciphertext with the same derived key.
pub fn decrypt(key: &SecretString, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    crypto::decrypt(key, ciphertext)
}

/// Verify the user-supplied TOTP code against the seed.
pub fn verify_totp(seed: &SecretString, code: &str) -> Result<bool, Error> {
    totp::verify_totp(seed, code)
}

/// Generate the current TOTP code for a seed.
pub fn generate_totp(seed: &SecretString) -> Result<String, Error> {
    totp::generate_totp(seed)
}
