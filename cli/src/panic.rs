use std::io::{self, Write};

use rpassword::prompt_password;
use secrecy::SecretString;
use vault_core::derive_key;
use vault_passwords::PasswordStore;

use crate::config::{load_config, save_config, Config};
use crate::confirm::confirm_or_cancel;
use crate::error::CliError;
use crate::keys;
use crate::paths::VaultLayout;
use crate::unlock::vault_salt;
use crate::wipe::{clear_vault_init_config, wipe_operational_vault};

pub fn run_panic() -> Result<(), CliError> {
    let mut config = load_config()?;
    let layout = VaultLayout::from_config(&config);

    confirm_or_cancel(
        "⚠️  PANIC destroys all local vault ciphertext on this machine.\n\
         Recovery requires your git snapshot and `nvlt system init --from-snapshot`.\n\
         Your offline backup key must remain off this machine.\n\
         \n\
         Continue? [y/N]: ",
    )?;

    print!("Type PANIC to confirm: ");
    io::stdout().flush().map_err(CliError::Io)?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(CliError::Io)?;
    if line.trim() != "PANIC" {
        return Err(CliError::Cancelled);
    }

    if layout.passwords.is_file() {
        verify_master_password(&config, &layout)?;
    }

    wipe_operational_vault(&config)?;
    clear_vault_init_config(&mut config);
    save_config(&config)?;

    println!("Local vault material removed. Agent session cleared.");
    println!("Restore: import or use your snapshot repo, then run `nvlt system init --from-snapshot --path <repo>`.");
    println!("Keep your offline backup key off this machine.");
    Ok(())
}

fn verify_master_password(config: &Config, layout: &VaultLayout) -> Result<(), CliError> {
    let password = SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?);
    let key_path = keys::prompt_key_path("Unlock key file path: ")?;
    keys::warn_key_custody(layout, &key_path);
    let key_secret = keys::load_identity_checked(&key_path)?;
    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();
    let data_key = derive_key(&password, &key_secret, &salt, params)?;
    if PasswordStore::load_path(&data_key, &layout.passwords).is_ok() {
        return Ok(());
    }
    Err(CliError::Config(
        "master password or key file did not verify against vault data; panic aborted".into(),
    ))
}
