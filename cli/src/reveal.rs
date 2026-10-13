use rpassword::prompt_password;
use secrecy::ExposeSecret;
use vault_core::verify_totp;

use crate::config::Config;
use crate::error::CliError;
use crate::paths::VaultLayout;
use crate::rate_limit::{
    self, burn_slot, load_primary_from_slot, select_active_slot,
};

#[derive(Debug, Clone, Copy)]
pub enum RevealRole {
    Primary,
    Backup,
}

pub fn run_reveal(config: &Config, role: RevealRole) -> Result<(), CliError> {
    let layout = VaultLayout::from_config(config);
    rate_limit::guard_device(config)?;
    rate_limit::ensure_rate_layout(config, &layout)?;
    let slot = select_active_slot(&layout, config)?;
    let params = config.kdf.to_kdf_params();
    let password = prompt_password("Master password: ").map_err(CliError::Io)?;
    let password = secrecy::SecretString::new(password);

    let (primary, backup) = match load_primary_from_slot(&layout, config, slot, &password, params) {
        Ok(seeds) => seeds,
        Err(e) => {
            let _ = burn_slot(&layout, slot);
            return Err(e);
        }
    };

    let (label, seed) = match role {
        RevealRole::Primary => ("primary", primary),
        RevealRole::Backup => ("backup", backup),
    };

    let code = prompt_password(format!("{label} authenticator code (6 digits): "))
        .map_err(CliError::Io)?;
    if !verify_totp(&seed, code.trim())? {
        let _ = burn_slot(&layout, slot);
        return Err(CliError::UnlockCancelled);
    }
    println!("{}", seed.expose_secret());
    Ok(())
}
