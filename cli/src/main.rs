#![forbid(unsafe_code)]

mod age_cmd;
mod agent;
mod commands;
mod config;
mod confirm;
mod error;
mod hardening;
mod keys;
mod lifecycle;
mod panic;
mod paths;
mod prompts;
mod snapshot;
mod ssh_cmd;
mod unlock;
mod wipe;

use age_cmd::{run_age, AgeCmd};
use clap::{Parser, Subcommand};
use commands::{
    run_env, run_files, run_pass, run_ssh, run_system, run_totp, EnvCmd, FilesCmd, PassCmd, SshCmd,
    SystemCmd, TotpCmd,
};
use error::CliError;
use owo_colors::OwoColorize;

#[derive(Parser, Debug)]
#[command(
    name = "nvlt",
    version,
    about = "Encrypted local vault (passwords, envs, files, TOTP, SSH)",
    long_about = "nvlt stores secrets as age-encrypted files under ~/.nvlt by default.\n\
        Unlock requires the master password AND a private key file kept off the machine.\n\
        Run `nvlt unlock --for 10m` on Unix to cache the session.\n\
        Lifecycle/admin commands live under `nvlt system`.\n\
        See `nvlt <command> --help` for usage.",
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Vault lifecycle and administration (init, status, backup, recover, rotate, snapshot, panic, config)
    System {
        #[command(subcommand)]
        cmd: SystemCmd,
    },
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
    /// age encrypt/decrypt/identity passthrough (no vault unlock required)
    Age {
        #[command(subcommand)]
        cmd: AgeCmd,
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
    /// SSH keys in ssh.age (add, activate under ~/.ssh)
    Ssh {
        #[command(subcommand)]
        cmd: SshCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AgentCmd {
    Run,
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
        Command::System { cmd } => run_system(cmd),
        Command::Unlock { duration } => unlock::run_unlock(&duration),
        Command::Lock => unlock::run_lock(),
        Command::Agent { cmd } => match cmd {
            AgentCmd::Run => agent::run_agent(),
        },
        Command::Age { cmd } => run_age(cmd),
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
