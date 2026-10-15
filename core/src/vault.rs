//! Public API surface for the core crate.

use secrecy::SecretString;

use crate::crypto;
use crate::error::Error;
use crate::identity;
use crate::kdf::{self, KdfParams};
use crate::totp;

/// Derive the vault data key from the master password, the private key
/// secret, and the salt.
pub fn derive_key(
    password: &SecretString,
    key_secret: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error> {
    kdf::derive_key(password, key_secret, salt, params)
}

/// Generate a fresh age X25519 identity (secret + public key).
pub fn generate_identity() -> Result<(SecretString, String), Error> {
    identity::generate_identity()
}

/// Derive the public key for a secret identity.
pub fn public_key(secret: &SecretString) -> Result<String, Error> {
    identity::public_key(secret)
}

/// True if the text parses as a plaintext age identity.
pub fn is_identity(text: &str) -> bool {
    identity::is_identity(text)
}

/// Load an age identity from a key file (plaintext or passphrase-wrapped).
pub fn load_identity(
    path: &std::path::Path,
    wrap_passphrase: Option<&SecretString>,
) -> Result<SecretString, Error> {
    identity::load_identity(path, wrap_passphrase)
}

/// Wrap an identity with a passphrase for storage.
pub fn wrap_identity(secret: &SecretString, passphrase: &SecretString) -> Result<Vec<u8>, Error> {
    identity::wrap_identity(secret, passphrase)
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
