use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("profile not found: {profile}")]
    ProfileNotFound { profile: String },

    #[error("variable not found: {profile} / {key}")]
    VarNotFound { profile: String, key: String },

    #[error("profile already exists: {profile}")]
    ProfileExists { profile: String },

    #[error("invalid env profile file")]
    InvalidFile,

    #[error(transparent)]
    Core(#[from] vault_core::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
