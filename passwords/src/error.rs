use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("entry not found: {domain} / {username}")]
    NotFound { domain: String, username: String },

    #[error("duplicate entry: {domain} / {username}")]
    Duplicate { domain: String, username: String },

    #[error("invalid passwords file")]
    InvalidFile,

    #[error(transparent)]
    Core(#[from] vault_core::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
