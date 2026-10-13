use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("SSH entry not found: {name}")]
    NotFound { name: String },

    #[error("duplicate SSH entry: {name}")]
    Duplicate { name: String },

    #[error("invalid ssh store file")]
    InvalidFile,

    #[error(transparent)]
    Core(#[from] vault_core::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
