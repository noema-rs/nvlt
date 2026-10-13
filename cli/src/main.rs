#![forbid(unsafe_code)]

mod agent;
mod commands;
mod config;
mod confirm;
mod error;
mod device;
mod hardening;
mod lifecycle;
mod nvlt_enc;
mod panic;
mod paths;
mod rate_limit;
mod rate_limit_cmd;
mod wipe;
mod prompts;
mod reveal;
mod ssh_cmd;
mod snapshot;
mod unlock;

use clap::{Parser, Subcommand};
use commands::{
    run_config, run_env, run_files, run_lifecycle, run_pass, run_reveal, run_snapshot, run_ssh,
    run_totp, ConfigCmd, EnvCmd, FilesCmd, LifecycleCmd, PassCmd, RevealCmd, SnapshotCmd, SshCmd,
    TotpCmd,
};
use error::CliError;
use owo_colors::OwoColorize;

#[derive(Parser, Debug)]
#[command(
    name = "nvlt",
    version,
    about = "Encrypted local vault (passwords, envs, files, TOTP, SSH)",
    long_about = "nvlt stores secrets as age-encrypted files under ~/.nvlt by default.\n\
        Unlock uses master password + primary TOTP (seeds in local nvlt.enc).\n\
        Use `nvlt unlock --for 10m` on Unix to cache the session.\n\
        Publish ciphertext via `nvlt snapshot export` (not nvlt.enc).\n\
        See `nvlt <command> --help` for usage."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new vault, or bootstrap from a snapshot (host.age)
    Init {
        /// Decrypt host.age into the vault, then prompt for vault credentials and write nvlt.enc
        #[arg(long)]
        from_snapshot: bool,
        /// Snapshot root (git clone with host.age); required with --from-snapshot
        #[arg(long, value_name = "PATH", requires = "from_snapshot")]
        path: Option<std::path::PathBuf>,
        /// Sync age private key (default: {path}/.nvlt-sync/host.key)
        #[arg(long, value_name = "PATH", requires = "from_snapshot")]
        identity: Option<std::path::PathBuf>,
    },
    /// Show vault path, initialization state, and agent session (Unix)
    Status,
    /// Cache the data key in a local agent (Unix only)
    Unlock {
        /// Idle TTL, e.g. 10m, 1h
        #[arg(long = "for", value_name = "DURATION", default_value = "10m")]
        duration: String,
    },
    /// Clear the cached agent session
    Lock,
    /// Internal agent daemon (do not run manually)
    #[command(hide = true)]
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// Refresh backup.age from current vault data (requires backup TOTP code)
    Backup,
    /// Restore vault data from backup.age and issue a new primary TOTP seed
    Recover,
    /// New master password and/or TOTP seeds; re-encrypt all stores and nvlt.enc
    Rotate,
    /// Export or import encrypted host.age snapshots for git sync
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCmd,
    },
    /// Mint new rate-limit duplas after failed attempts (offline bundle + key)
    RateLimit {
        #[command(subcommand)]
        cmd: RateLimitCmd,
    },
    /// Emergency local wipe of ciphertext and rate duplas; restore via git snapshot and init --from-snapshot
    Panic,
    /// Print a TOTP seed to stdout after verification (sensitive)
    Reveal {
        #[command(subcommand)]
        cmd: RevealCmd,
    },
    /// Bootstrap path and vault config.toml settings
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Credential store keyed by (domain, username)
    Pass {
        #[command(subcommand)]
        cmd: PassCmd,
    },
    /// Encrypted environment variable profiles
    #[command(name = "env")]
    Env {
        #[command(subcommand)]
        cmd: EnvCmd,
    },
    /// Encrypt arbitrary files into the vault
    Files {
        #[command(subcommand)]
        cmd: FilesCmd,
    },
    /// Standalone TOTP seeds (not tied to a password entry)
    Totp {
        #[command(subcommand)]
        cmd: TotpCmd,
    },
    /// SSH keys in ssh.age (register, activate under ~/.ssh)
    Ssh {
        #[command(subcommand)]
        cmd: SshCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AgentCmd {
    Run,
}

#[derive(Subcommand, Debug)]
enum RateLimitCmd {
    /// Replace rate/ duplas using recovery bundle and rate-limit private key
    Renew {
        #[arg(long, value_name = "PATH")]
        bundle: std::path::PathBuf,
        #[arg(long = "rate-limit-key", value_name = "PATH")]
        rate_limit_key: std::path::PathBuf,
    },
}

fn main() -> miette::Result<()> {
    let _ = hardening::disable_core_dumps();
    let cli = Cli::parse();
    if let Err(err) = dispatch(cli.command) {
        eprintln!("{}: {err}", "Error".red().bold());
        std::process::exit(1);
    }
    Ok(())
}

fn dispatch(command: Command) -> Result<(), CliError> {
    match command {
        Command::Init {
            from_snapshot,
            path,
            identity,
        } => run_lifecycle(LifecycleCmd::Init {
            from_snapshot,
            path,
            identity,
        }),
        Command::Status => run_lifecycle(LifecycleCmd::Status),
        Command::Unlock { duration } => unlock::run_unlock(&duration),
        Command::Lock => unlock::run_lock(),
        Command::Agent { cmd } => match cmd {
            AgentCmd::Run => agent::run_agent(),
        },
        Command::Backup => run_lifecycle(LifecycleCmd::Backup),
        Command::Recover => run_lifecycle(LifecycleCmd::Recover),
        Command::Rotate => run_lifecycle(LifecycleCmd::Rotate),
        Command::Snapshot { cmd } => run_snapshot(cmd),
        Command::RateLimit { cmd } => match cmd {
            RateLimitCmd::Renew {
                bundle,
                rate_limit_key,
            } => rate_limit_cmd::run_renew(bundle, rate_limit_key),
        },
        Command::Panic => panic::run_panic(),
        Command::Reveal { cmd } => run_reveal(cmd),
        Command::Config { cmd } => run_config(cmd),
        Command::Pass { cmd } => run_pass(cmd),
        Command::Env { cmd } => run_env(cmd),
        Command::Files { cmd } => run_files(cmd),
        Command::Totp { cmd } => run_totp(cmd),
        Command::Ssh { cmd } => run_ssh(cmd),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_help_smoke() {
        Cli::command().debug_assert();
    }
}
