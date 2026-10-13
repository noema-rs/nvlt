use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("encrypted file not found: {name}")]
    NotFound { name: String },

    #[error("encrypted file already exists: {name}")]
    AlreadyExists { name: String },

    #[error("source path has no file name")]
    InvalidSourcePath,

    #[error(transparent)]
    Core(#[from] vault_core::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
