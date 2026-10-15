use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("key derivation failed")]
    Kdf,

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed")]
    Decrypt,

    #[error("invalid TOTP seed")]
    InvalidTotpSeed,

    #[error("TOTP verification failed")]
    TotpVerify,

    #[error("TOTP generation failed")]
    TotpGenerate,

    #[error("invalid vault lock")]
    InvalidLock,

    #[error("invalid or unreadable key file")]
    KeyFile,
}
