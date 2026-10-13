use thiserror::Error;

#[derive(Debug, Error, miette::Diagnostic)]
pub enum CliError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("vault is not initialized (missing lock in config or vault data)")]
    NotInitialized,

    #[error(
        "vault already initialized at {vault_root}. \
         Use `nvlt init --from-snapshot` or `snapshot import`, or recover from backup."
    )]
    AlreadyInitialized { vault_root: std::path::PathBuf },

    #[error("unlock cancelled")]
    UnlockCancelled,

    #[error(
        "device fingerprint mismatch; local vault files were wiped. \
         Restore with `nvlt init --from-snapshot` or your offline recovery bundle."
    )]
    DeviceMismatch,

    #[error(
        "no valid rate-limit tokens remain; run `nvlt rate-limit renew` with offline bundle and rate-limit key"
    )]
    RateLimitExhausted,

    #[error("TOTP setup verification failed for {label}; check the seed/QR and your authenticator app")]
    TotpSetupVerifyFailed { label: String },

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
