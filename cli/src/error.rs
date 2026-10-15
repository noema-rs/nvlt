use thiserror::Error;

#[derive(Debug, Error, miette::Diagnostic)]
pub enum CliError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("vault is not initialized (missing lock in config or vault data)")]
    NotInitialized,

    #[error(
        "vault already initialized at {vault_root}. \
         Use `nvlt system init --from-snapshot` or `nvlt system snapshot import`, or `nvlt system recover`."
    )]
    AlreadyInitialized { vault_root: std::path::PathBuf },

    #[error("operation cancelled")]
    Cancelled,

    #[error(transparent)]
    Core(#[from] vault_core::Error),

    #[error(transparent)]
    Passwords(#[from] vault_passwords::Error),

    #[error(transparent)]
    Envs(#[from] vault_envs::Error),

    #[error(transparent)]
    Files(#[from] vault_files::Error),

    #[error(transparent)]
    Totp(#[from] vault_totp::Error),

    #[error(transparent)]
    Ssh(#[from] vault_ssh::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Agent socket missing or not accepting connections (not a user-facing fatal error).
    #[error("vault agent is not running")]
    AgentUnavailable,
}
