use std::io::{self, Write};

use rpassword::prompt_password;
use secrecy::SecretString;
use vault_core::derive_key;
use vault_passwords::PasswordStore;

use crate::config::{load_config, save_config, Config};
use crate::confirm::confirm_or_cancel;
use crate::error::CliError;
use crate::paths::VaultLayout;
use crate::rate_limit::{self, RATE_SLOT_COUNT};
use crate::unlock::vault_salt;
use crate::wipe::{clear_vault_init_config, wipe_operational_vault};

pub fn run_panic() -> Result<(), CliError> {
    let mut config = load_config()?;
    let layout = VaultLayout::from_config(&config);

    confirm_or_cancel(
        "⚠️  PANIC destroys all local vault ciphertext and rate duplas on this machine.\n\
         Recovery requires your git snapshot and `nvlt init --from-snapshot`.\n\
         Offline recovery bundle must remain off this machine.\n\
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
    println!("Restore: import or use your snapshot repo, then run `nvlt init --from-snapshot --path <repo>`.");
    Ok(())
}

fn verify_master_password(config: &Config, layout: &VaultLayout) -> Result<(), CliError> {
    let password = SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?);
    let salt = vault_salt(config)?;
    let params = config.kdf.to_kdf_params();

    if layout.has_rate_duplas() {
        if let Ok(vk) = rate_limit::verifying_key_from_config(config) {
            let generation = config.vault.rate_generation.unwrap_or(0);
            let device_id = config
                .vault
                .device_id
                .as_deref()
                .unwrap_or("");
            for slot in 1..=RATE_SLOT_COUNT {
                if rate_limit::slot_valid_for_panic(layout, config, slot, &vk, generation, device_id)
                    .is_err()
                {
                    continue;
                }
                if let Ok((primary, _)) =
                    rate_limit::load_primary_from_slot(layout, config, slot, &password, params)
                {
                    let data_key = derive_key(&password, &primary, &salt, params)?;
                    if PasswordStore::load_path(&data_key, &layout.passwords).is_ok() {
                        return Ok(());
                    }
                }
            }
        }
    }

    if layout.nvlt_enc.is_file() {
        let primary = crate::nvlt_enc::load_primary_seed_only(layout, &password, params)?;
        let data_key = derive_key(&password, &primary, &salt, params)?;
        if PasswordStore::load_path(&data_key, &layout.passwords).is_ok() {
            return Ok(());
        }
    }

    Err(CliError::Config(
        "master password did not verify against vault data; panic aborted".into(),
    ))
}
