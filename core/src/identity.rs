use std::fs;
use std::path::Path;

use age::secrecy::ExposeSecret as AgeExposeSecret;
use secrecy::{ExposeSecret, SecretString};

use crate::crypto;
use crate::error::Error;

/// Generate a fresh age X25519 identity.
///
/// Returns the secret identity (`AGE-SECRET-KEY-1…`) and its public key (`age1…`).
pub fn generate_identity() -> Result<(SecretString, String), Error> {
    let identity = age::x25519::Identity::generate();
    let secret_text = identity.to_string();
    let secret = SecretString::new(AgeExposeSecret::expose_secret(&secret_text).to_string());
    let public = identity.to_public().to_string();
    Ok((secret, public))
}

/// Derive the public key (`age1…`) for a secret identity string.
pub fn public_key(secret: &SecretString) -> Result<String, Error> {
    let identity: age::x25519::Identity =
        secret.expose_secret().parse().map_err(|_| Error::KeyFile)?;
    Ok(identity.to_public().to_string())
}

/// Find the first `AGE-SECRET-KEY-1…` identity line, ignoring blank lines and
/// `#` comments (as produced by `age-keygen`).
fn find_identity(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find(|line| line.parse::<age::x25519::Identity>().is_ok())
        .map(str::to_string)
}

/// True if the bytes parse as a plaintext `AGE-SECRET-KEY-1…` identity.
pub fn is_identity(text: &str) -> bool {
    find_identity(text).is_some()
}

/// Load an age X25519 identity from a key file.
///
/// The file may hold a plaintext identity or, when `wrap_passphrase` is
/// supplied, an identity encrypted with that passphrase.
pub fn load_identity(
    path: &Path,
    wrap_passphrase: Option<&SecretString>,
) -> Result<SecretString, Error> {
    let bytes = fs::read(path).map_err(|_| Error::KeyFile)?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Some(identity) = find_identity(text) {
            return Ok(SecretString::new(identity));
        }
    }
    if let Some(passphrase) = wrap_passphrase {
        let plaintext = crypto::decrypt(passphrase, &bytes)?;
        let text = String::from_utf8(plaintext).map_err(|_| Error::KeyFile)?;
        if let Some(identity) = find_identity(&text) {
            return Ok(SecretString::new(identity));
        }
    }
    Err(Error::KeyFile)
}

/// Wrap an identity with a passphrase for storage on disk.
pub fn wrap_identity(secret: &SecretString, passphrase: &SecretString) -> Result<Vec<u8>, Error> {
    crypto::encrypt(passphrase, secret.expose_secret().as_bytes())
}
