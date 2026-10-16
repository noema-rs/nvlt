use std::path::PathBuf;

use clap::Subcommand;
use rpassword::prompt_password;
use vault_envs::EnvVault;
use vault_files::{FileVault, OverwritePolicy};
use vault_passwords::{EntryUpdate, NewEntry, PasswordStore};
use vault_totp::{default_entry, TotpStore};

use crate::config::{load_config, save_config, set_config_key, show_config};
use crate::confirm::confirm_or_cancel;
use crate::error::CliError;
use crate::lifecycle;
use crate::paths::VaultLayout;
use crate::prompts::{
    prompt_extra_fields, prompt_extra_fields_edit, prompt_notes, prompt_optional_embedded_totp,
    prompt_password_keep, prompt_password_required, prompt_totp_edit,
};
use crate::unlock::UnlockSession;

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print bootstrap (~/.config/nvlt) and vault config.toml
    Show,
    /// Set a key (e.g. vault.path, sync.host_file, kdf.memory_cost)
    Set { key: String, value: String },
    /// Set bootstrap vault root path
    Path { path: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum PassCmd {
    /// List all entries
    List,
    /// Search by domain; optional --user filter
    Search {
        domain: String,
        #[arg(long)]
        user: Option<String>,
    },
    /// Show password, TOTP, and fields for one entry
    Get { domain: String, username: String },
    /// Interactive add for a domain
    Add { domain: String },
    /// Interactive edit (confirms overwrite)
    Edit { domain: String, username: String },
    /// Delete one entry (confirms)
    Remove { domain: String, username: String },
}

#[derive(Subcommand, Debug)]
pub enum EnvCmd {
    /// List profiles, or keys in one profile
    List { profile: Option<String> },
    /// Get one variable value
    Get { profile: String, key: String },
    /// Set a variable (creates profile if needed)
    Set {
        profile: String,
        key: String,
        value: String,
    },
    /// Remove one key (confirms)
    Unset { profile: String, key: String },
    /// Create an empty profile
    Add { profile: String },
    /// Delete a profile (confirms)
    Remove { profile: String },
    /// Print export KEY=... lines to stdout
    Export { profile: String },
    /// Shell wrapper evaluates export output (see INIT.md)
    Load { profile: String },
    /// Interactively set variables on a profile
    Edit { profile: String },
    /// Import KEY=VALUE lines from a file (path prompted when omitted)
    Import {
        profile: String,
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum FilesCmd {
    /// List encrypted filenames in the vault
    List,
    /// Encrypt a file into files/ (confirms overwrite)
    Encrypt {
        /// Source file; prompted when omitted
        path: Option<PathBuf>,
        /// Stored vault filename; prompted when omitted
        name: Option<String>,
    },
    /// Decrypt to path or --stdout (confirms overwrite)
    Decrypt {
        name: String,
        /// Output path; prompted when omitted (unless --stdout)
        output_path: Option<PathBuf>,
        #[arg(long)]
        stdout: bool,
    },
    /// Delete encrypted file (confirms)
    Remove { name: String },
}

#[derive(Subcommand, Debug)]
pub enum TotpCmd {
    /// List standalone TOTP sites
    List,
    /// Add a standalone seed
    Add { site: String },
    /// Show current 6-digit code
    Get { site: String },
    /// Remove entry (confirms)
    Remove { site: String },
    /// Write QR image for migration
    Export { site: String, path: PathBuf },
    /// Import from QR or seed file
    Import { path: PathBuf },
}

pub fn run_config(cmd: ConfigCmd) -> Result<(), CliError> {
    let mut config = load_config()?;
    match cmd {
        ConfigCmd::Show => {
            print!("{}", show_config(&config));
        }
        ConfigCmd::Set { key, value } => {
            set_config_key(&mut config, &key, &value)?;
            save_config(&config)?;
        }
        ConfigCmd::Path { path } => {
            config.vault.path = path;
            save_config(&config)?;
        }
    }
    Ok(())
}

pub fn run_pass(cmd: PassCmd) -> Result<(), CliError> {
    let config = load_config()?;
    let layout = VaultLayout::from_config(&config);
    let session = UnlockSession::unlock_data_key(&config, &layout)?;
    let mut store = PasswordStore::load_path(&session.data_key, &layout.passwords)?;

    match cmd {
        PassCmd::List => {
            for entry in store.list() {
                println!("{} ({})", entry.domain, entry.username);
            }
        }
        PassCmd::Search { domain, user } => {
            for entry in store.search(&domain, user.as_deref()) {
                println!("{} ({})", entry.domain, entry.username);
            }
        }
        PassCmd::Get { domain, username } => {
            let entry = store.get(&domain, &username)?;
            println!("{} ({})", entry.domain, entry.username);
            println!("Password:    {}", entry.password);
            if let Some(totp) = entry.current_totp()? {
                println!(
                    "TOTP:        {} (expires in {}s)",
                    totp.code, totp.seconds_remaining
                );
            }
            if !entry.notes.is_empty() {
                println!("Notes:       {}", entry.notes);
            }
            if !entry.fields.is_empty() {
                println!("Fields:");
                for field in &entry.fields {
                    println!("  {}: {}", field.key, field.value);
                }
            }
        }
        PassCmd::Add { domain } => {
            let username = crate::prompts::prompt_line("Username: ")?;
            let password = prompt_password_required("Password: ")?;
            let totp = prompt_optional_embedded_totp()?;
            let notes = prompt_notes("Notes (optional): ")?;
            let fields = prompt_extra_fields()?;
            store.add(NewEntry {
                domain,
                username,
                password,
                totp,
                notes,
                fields,
            })?;
            store.save_path(&session.data_key, &layout.passwords)?;
        }
        PassCmd::Edit { domain, username } => {
            let confirmation = store.prepare_edit(&domain, &username)?;
            confirm_or_cancel(&confirmation.prompt)?;
            let existing = store.get(&domain, &username)?;
            let password = match prompt_password_keep("New password (empty to keep): ")? {
                Some(p) => p,
                None => existing.password.clone(),
            };
            let totp = match prompt_totp_edit(existing.totp.as_ref())? {
                Some(t) => t,
                None => existing.totp.clone(),
            };
            let notes = {
                let n = prompt_notes("Notes (empty to keep): ")?;
                if n.is_empty() {
                    existing.notes.clone()
                } else {
                    n
                }
            };
            let fields = match prompt_extra_fields_edit(&existing.fields)? {
                Some(f) => f,
                None => existing.fields.clone(),
            };
            store.edit(
                &domain,
                &username,
                EntryUpdate {
                    password,
                    totp,
                    notes,
                    fields,
                },
            )?;
            store.save_path(&session.data_key, &layout.passwords)?;
        }
        PassCmd::Remove { domain, username } => {
            let confirmation = store.prepare_remove(&domain, &username)?;
            confirm_or_cancel(&confirmation.prompt)?;
            store.remove(&domain, &username)?;
            store.save_path(&session.data_key, &layout.passwords)?;
        }
    }
    Ok(())
}

pub fn run_env(cmd: EnvCmd) -> Result<(), CliError> {
    let config = load_config()?;
    let layout = VaultLayout::from_config(&config);
    let vault = EnvVault::new(&layout.envs_dir);

    match cmd {
        EnvCmd::List { profile } => {
            if let Some(name) = profile {
                let session = UnlockSession::unlock_data_key(&config, &layout)?;
                let store = vault.load_profile(&name, &session.data_key)?;
                for key in store.list_keys() {
                    println!("{key}");
                }
            } else {
                for name in vault.list_profiles()? {
                    println!("{name}");
                }
            }
        }
        EnvCmd::Get { profile, key } => {
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            let store = vault.load_profile(&profile, &session.data_key)?;
            println!("{}", store.get(&key)?);
        }
        EnvCmd::Set {
            profile,
            key,
            value,
        } => {
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            vault.set_var(&profile, &key, &value, &session.data_key)?;
        }
        EnvCmd::Unset { profile, key } => {
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            let store = vault.load_profile(&profile, &session.data_key)?;
            confirm_or_cancel(&vault_envs::unset_confirmation(&profile, &key).prompt)?;
            let mut store = store;
            store.unset(&key)?;
            vault.save_profile(&store, &session.data_key)?;
        }
        EnvCmd::Add { profile } => {
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            vault.add_profile(&profile, &session.data_key)?;
        }
        EnvCmd::Remove { profile } => {
            confirm_or_cancel(&vault.prepare_remove_profile(&profile)?.prompt)?;
            vault.remove_profile(&profile)?;
        }
        EnvCmd::Export { profile } | EnvCmd::Load { profile } => {
            env_export_profile(&config, &layout, &vault, &profile)?;
        }
        EnvCmd::Edit { profile } => {
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            let mut store = match vault.load_profile(&profile, &session.data_key) {
                Ok(s) => s,
                Err(vault_envs::Error::ProfileNotFound { .. }) => {
                    vault.add_profile(&profile, &session.data_key)?;
                    vault.load_profile(&profile, &session.data_key)?
                }
                Err(e) => return Err(e.into()),
            };
            println!("Editing profile \"{profile}\" (empty key to finish).");
            loop {
                let key = crate::prompts::prompt_line("Variable key: ")?;
                if key.is_empty() {
                    break;
                }
                let value = crate::prompts::prompt_line("Value: ")?;
                store.set(key, value);
            }
            vault.save_profile(&store, &session.data_key)?;
        }
        EnvCmd::Import { profile, path } => {
            let path = match path {
                Some(p) => p,
                None => crate::keys::prompt_key_path("Env file path to import: ")?,
            };
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            vault.import_dotenv_file(&profile, &path, &session.data_key)?;
            println!("Imported variables into profile \"{profile}\" from {}.", path.display());
        }
    }
    Ok(())
}

fn env_export_profile(
    config: &crate::config::Config,
    layout: &VaultLayout,
    vault: &EnvVault,
    profile: &str,
) -> Result<(), CliError> {
    let session = UnlockSession::unlock_data_key(config, layout)?;
    let store = vault.load_profile(profile, &session.data_key)?;
    for line in store.export_lines() {
        println!("{line}");
    }
    Ok(())
}

pub fn run_files(cmd: FilesCmd) -> Result<(), CliError> {
    let config = load_config()?;
    let layout = VaultLayout::from_config(&config);
    let vault = FileVault::new(&layout.files_dir);

    match cmd {
        FilesCmd::List => {
            for name in vault.list()? {
                println!("{name}");
            }
        }
        FilesCmd::Encrypt { path, name } => {
            let path = match path {
                Some(p) => p,
                None => crate::keys::prompt_key_path("Source file path: ")?,
            };
            let vault_name = match name {
                Some(n) => n,
                None => crate::prompts::prompt_line("Vault filename (under files/): ")?,
            };
            if vault_name.is_empty() {
                return Err(CliError::Config("vault filename is required".into()));
            }
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            let dest = layout.files_dir.join(&vault_name);
            let overwrite = if dest.exists() {
                confirm_or_cancel(&format!(
                    "⚠️  You are about to encrypt: {}\n\
                        The encrypted copy will be stored in: {}\n\
                        If a file with the same name already exists, it will be OVERWRITTEN.\n\
                     \n\
                        Continue? [y/N]: ",
                    path.display(),
                    dest.display()
                ))?;
                OverwritePolicy::Allow
            } else {
                confirm_or_cancel(&format!(
                    "⚠️  You are about to encrypt: {}\n\
                        The encrypted copy will be stored in: {}\n\
                     \n\
                        Continue? [y/N]: ",
                    path.display(),
                    dest.display()
                ))?;
                OverwritePolicy::RefuseIfExists
            };
            let stored =
                vault.encrypt_file_as(&path, &vault_name, &session.data_key, overwrite)?;
            println!("Stored as {stored}");
        }
        FilesCmd::Decrypt {
            name,
            output_path,
            stdout,
        } => {
            let session = UnlockSession::unlock_data_key(&config, &layout)?;
            if stdout {
                let bytes = vault.decrypt_stdout(&name, &session.data_key)?;
                use std::io::Write;
                std::io::stdout().write_all(&bytes).map_err(CliError::Io)?;
            } else {
                let dest = match output_path {
                    Some(p) => p,
                    None => crate::keys::prompt_key_path("Output file path: ")?,
                };
                if dest.exists() {
                    confirm_or_cancel(&format!(
                        "⚠️  You are about to decrypt: {name}\n\
                            Output will be written to: {}\n\
                            If a file already exists at that path, it will be OVERWRITTEN.\n\
                         \n\
                            Continue? [y/N]: ",
                        dest.display()
                    ))?;
                }
                vault.decrypt_to_path(&name, dest, &session.data_key)?;
            }
        }
        FilesCmd::Remove { name } => {
            confirm_or_cancel(&format!(
                "⚠️  You are about to delete the encrypted file: {name}\n\
                    This action cannot be undone.\n\
                 \n\
                    Delete this file? [y/N]: "
            ))?;
            vault.remove(&name)?;
        }
    }
    Ok(())
}

pub fn run_totp(cmd: TotpCmd) -> Result<(), CliError> {
    let config = load_config()?;
    let layout = VaultLayout::from_config(&config);
    let session = UnlockSession::unlock_data_key(&config, &layout)?;
    let mut store = TotpStore::load_path(&session.data_key, &layout.totp)?;

    match cmd {
        TotpCmd::List => {
            for entry in store.list() {
                println!("{} ({})", entry.site, entry.account);
            }
        }
        TotpCmd::Add { site } => {
            let account = crate::prompts::prompt_line("Account label: ")?;
            let seed = prompt_password("TOTP seed (base32): ").map_err(CliError::Io)?;
            store.add(default_entry(site, account, seed.trim()))?;
            store.save_path(&session.data_key, &layout.totp)?;
        }
        TotpCmd::Get { site } => {
            let entry = store.get(&site)?;
            let code = entry.current_code()?;
            println!(
                "{}: {} (expires in {}s)",
                site, code.code, code.seconds_remaining
            );
        }
        TotpCmd::Remove { site } => {
            let confirmation = store.prepare_remove(&site)?;
            confirm_or_cancel(&confirmation.prompt)?;
            store.remove(&site)?;
            store.save_path(&session.data_key, &layout.totp)?;
        }
        TotpCmd::Export { site, path } => {
            store.export_to_path(&site, path)?;
        }
        TotpCmd::Import { path } => {
            store.import_from_path(path)?;
            store.save_path(&session.data_key, &layout.totp)?;
        }
    }
    Ok(())
}

pub fn run_system(cmd: SystemCmd) -> Result<(), CliError> {
    match cmd {
        SystemCmd::Init {
            from_snapshot,
            path,
            identity,
        } => {
            if from_snapshot {
                let path = path.ok_or_else(|| {
                    CliError::Config("--path is required with --from-snapshot".into())
                })?;
                lifecycle::init_from_snapshot(path, identity)
            } else {
                let mut config = load_config()?;
                lifecycle::init(&mut config)
            }
        }
        SystemCmd::Status => {
            let config = load_config()?;
            lifecycle::status(&config)
        }
        SystemCmd::Backup => {
            let config = load_config()?;
            lifecycle::backup(&config)
        }
        SystemCmd::Recover => {
            let config = load_config()?;
            lifecycle::recover(&config)
        }
        SystemCmd::Rotate => {
            let config = load_config()?;
            lifecycle::rotate(&config)
        }
        SystemCmd::Snapshot { cmd } => run_snapshot(cmd),
        SystemCmd::Panic => crate::panic::run_panic(),
        SystemCmd::Config { cmd } => run_config(cmd),
    }
}

#[derive(Subcommand, Debug)]
pub enum SystemCmd {
    /// Create a new vault, or bootstrap from a snapshot (host.age)
    Init {
        /// Decrypt host.age into the vault, then prompt for the master password and main key
        #[arg(long)]
        from_snapshot: bool,
        /// Snapshot root (git clone with host.age); required with --from-snapshot
        #[arg(long, value_name = "PATH", requires = "from_snapshot")]
        path: Option<PathBuf>,
        /// Sync age private key (default: {path}/.nvlt-sync/host.key)
        #[arg(long, value_name = "PATH", requires = "from_snapshot")]
        identity: Option<PathBuf>,
    },
    /// Show vault path, initialization state, and agent session (Unix)
    Status,
    /// Refresh backup.age from current vault data (requires the backup key)
    Backup,
    /// Restore vault data from backup.age and issue a new main unlock key
    Recover,
    /// Change master password and/or unlock keys; re-encrypt all stores and backup
    Rotate,
    /// Export or import encrypted host.age snapshots for git sync
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCmd,
    },
    /// Emergency local wipe of ciphertext; restore via git snapshot and init --from-snapshot
    Panic,
    /// Bootstrap path and vault config.toml settings
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum SnapshotCmd {
    /// Run backup, then write host.age + host.pub under --path (sync host passphrase)
    Export {
        /// Git clone or directory containing host.age (uses .nvlt-sync/host.key)
        #[arg(long)]
        path: PathBuf,
    },
    /// Decrypt host.age into vault root (confirms overwrite)
    Import {
        #[arg(long)]
        path: PathBuf,
    },
}

pub fn run_snapshot(cmd: SnapshotCmd) -> Result<(), CliError> {
    let config = load_config()?;
    match cmd {
        SnapshotCmd::Export { path } => crate::snapshot::snapshot_export(&config, &path),
        SnapshotCmd::Import { path } => crate::snapshot::snapshot_import(&config, &path),
    }
}

#[derive(Subcommand, Debug)]
pub enum SshCmd {
    /// Copy key material into ssh.age
    Register {
        name: String,
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        public: Option<PathBuf>,
    },
    /// List registered keys
    List,
    /// Symlink private key into ~/.ssh (tracked for deactivate)
    Activate { name: String },
    /// Remove symlinks created by activate
    Deactivate { name: String },
    /// Remove from ssh.age (confirms)
    Remove { name: String },
    /// Run ssh using stored host/user when set
    Open { name: String },
}

pub fn run_ssh(cmd: SshCmd) -> Result<(), CliError> {
    let config = load_config()?;
    match cmd {
        SshCmd::Register { name, path, public } => {
            crate::ssh_cmd::register(&config, name, path, public)
        }
        SshCmd::List => crate::ssh_cmd::list(&config),
        SshCmd::Activate { name } => crate::ssh_cmd::activate(&config, &name),
        SshCmd::Deactivate { name } => crate::ssh_cmd::deactivate(&config, &name),
        SshCmd::Remove { name } => crate::ssh_cmd::remove(&config, &name),
        SshCmd::Open { name } => crate::ssh_cmd::open(&config, &name),
    }
}
