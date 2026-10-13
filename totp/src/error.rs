use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("TOTP entry not found: {site}")]
    NotFound { site: String },

    #[error("duplicate TOTP entry: {site}")]
    Duplicate { site: String },

    #[error("invalid totp store file")]
    InvalidFile,

    #[error("invalid otpauth URI")]
    InvalidOtpAuth,

    #[error("image processing failed")]
    Image,

    #[error(transparent)]
    Core(#[from] vault_core::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
