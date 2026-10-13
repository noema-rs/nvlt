use secrecy::{ExposeSecret, SecretString};

/// Concatenate password and TOTP seed for KDF input (`password || seed`).
pub fn composite_passphrase(password: &SecretString, seed: &SecretString) -> SecretString {
    let mut combined = String::new();
    combined.push_str(password.expose_secret());
    combined.push_str(seed.expose_secret());
    SecretString::new(combined)
}
