use std::io::{Read, Write};
use std::iter;

use age::secrecy::SecretString as AgeSecretString;
use secrecy::{ExposeSecret, SecretString};

use crate::error::Error;

fn age_passphrase(key: &SecretString) -> AgeSecretString {
    AgeSecretString::from(key.expose_secret().clone())
}

/// Encrypt plaintext with age scrypt passphrase mode using the derived key hex as passphrase.
pub fn encrypt(key: &SecretString, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let passphrase = age_passphrase(key);
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

    let mut ciphertext = vec![];
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| Error::Encrypt)?;
    writer.write_all(plaintext).map_err(|_| Error::Encrypt)?;
    writer.finish().map_err(|_| Error::Encrypt)?;

    Ok(ciphertext)
}

/// Decrypt age ciphertext with the same key material used for encryption.
pub fn decrypt(key: &SecretString, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let passphrase = age_passphrase(key);
    let decryptor = age::Decryptor::new(ciphertext).map_err(|_| Error::Decrypt)?;
    let identity = age::scrypt::Identity::new(passphrase);

    let mut reader = decryptor
        .decrypt(iter::once(&identity as _))
        .map_err(|_| Error::Decrypt)?;

    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| Error::Decrypt)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{self, KdfParams};
    use secrecy::SecretString;

    fn test_key() -> SecretString {
        let password = SecretString::new("password".to_string());
        let seed = SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string());
        kdf::derive_key(
            &password,
            &seed,
            b"vault-test-salt!",
            KdfParams::fast_test(),
        )
        .unwrap()
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let plaintext = b"vault secret payload";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key = test_key();
        let ciphertext = encrypt(&key, b"data").unwrap();

        let other = kdf::derive_key(
            &SecretString::new("other".to_string()),
            &SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            b"vault-test-salt!",
            KdfParams::fast_test(),
        )
        .unwrap();

        assert!(decrypt(&other, &ciphertext).is_err());
    }
}
