use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::Error;

const LOCK_INFO: &[u8] = b"nvlt-lock-v1";

/// Derive the 16-byte Argon2 salt from the vault `lock` string (never persisted on disk).
pub fn salt_from_lock(lock: &str) -> Result<[u8; 16], Error> {
    if lock.is_empty() {
        return Err(Error::InvalidLock);
    }
    let hk = Hkdf::<Sha256>::new(None, lock.as_bytes());
    let mut okm = [0u8; 16];
    hk.expand(LOCK_INFO, &mut okm)
        .map_err(|_| Error::InvalidLock)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_salt_is_deterministic() {
        let a = salt_from_lock("test-lock-value-abc").unwrap();
        let b = salt_from_lock("test-lock-value-abc").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_locks_differ() {
        let a = salt_from_lock("lock-a").unwrap();
        let b = salt_from_lock("lock-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_lock_rejected() {
        assert!(salt_from_lock("").is_err());
    }
}
