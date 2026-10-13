use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use secrecy::SecretString;
use vault_core::{derive_key, verify_totp};
use vault_passwords::PasswordStore;

use crate::config::{load_config, save_config};
use crate::error::CliError;
use crate::paths::VaultLayout;
use rpassword::prompt_password;
use crate::rate_limit::{read_recovery_bundle, renew_duplas};
use crate::unlock::vault_salt;

pub fn run_renew(bundle: PathBuf, rate_limit_key: PathBuf) -> Result<(), CliError> {
    let mut config = load_config()?;
    let layout = VaultLayout::from_config(&config);
    if !layout.is_initialized(&config) {
        return Err(CliError::NotInitialized);
    }

    let recovery_pass = SecretString::new(
        prompt_password("Recovery bundle passphrase: ").map_err(CliError::Io)?,
    );
    let plain = read_recovery_bundle(&bundle, &recovery_pass)?;

    let key_pem = std::fs::read(&rate_limit_key)?;
    let signing = signing_key_from_pem_or_raw(&key_pem, &plain)?;

    let password = SecretString::new(prompt_password("Master password: ").map_err(CliError::Io)?);
    let primary = SecretString::new(plain.primary.clone());
    let backup = SecretString::new(plain.backup.clone());
    let salt = vault_salt(&config)?;
    let params = config.kdf.to_kdf_params();
    let data_key = derive_key(&password, &primary, &salt, params)?;
    if PasswordStore::load_path(&data_key, &layout.passwords).is_err() {
        return Err(CliError::Config(
            "master password or bundle seeds did not match vault".into(),
        ));
    }
    let code = prompt_password("Primary authenticator code (6 digits): ").map_err(CliError::Io)?;
    if !verify_totp(&primary, code.trim())? {
        return Err(CliError::UnlockCancelled);
    }

    renew_duplas(
        &mut config,
        &layout,
        &plain,
        &password,
        &primary,
        &backup,
        params,
    )?;
    save_config(&config)?;
    println!(
        "Rate-limit duplas renewed (generation {}). {} slots minted under {}.",
        config.vault.rate_generation.unwrap_or(0),
        crate::rate_limit::RATE_SLOT_COUNT,
        layout.rate_dir.display()
    );
    let _ = signing;
    Ok(())
}

fn signing_key_from_pem_or_raw(
    key_bytes: &[u8],
    plain: &crate::rate_limit::RecoveryPlaintext,
) -> Result<SigningKey, CliError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let expected = STANDARD
        .decode(&plain.rate_limit_secret_key_b64)
        .map_err(|_| CliError::Config("invalid bundle signing key".into()))?;
    let trimmed = std::str::from_utf8(key_bytes)
        .map(|s| s.trim())
        .unwrap_or("");
    let raw = if trimmed.starts_with("-----") {
        return Err(CliError::Config(
            "rate-limit key must be raw 32-byte Ed25519 secret (base64 file supported)".into(),
        ));
    } else if trimmed.is_empty() {
        return Err(CliError::Config("empty rate-limit key file".into()));
    } else if trimmed.is_ascii() {
        STANDARD
            .decode(trimmed.as_bytes())
            .map_err(|_| CliError::Config("invalid rate-limit key encoding".into()))?
    } else {
        key_bytes.to_vec()
    };
    if raw != expected {
        return Err(CliError::Config(
            "rate-limit private key does not match recovery bundle".into(),
        ));
    }
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| CliError::Config("invalid rate-limit key length".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}
