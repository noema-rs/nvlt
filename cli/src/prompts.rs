use rpassword::prompt_password;
use vault_passwords::{default_embedded_totp, EmbeddedTotp, ExtraField};

use crate::confirm::confirm;
use crate::error::CliError;

pub fn prompt_line(label: &str) -> Result<String, CliError> {
    print!("{label}");
    std::io::Write::flush(&mut std::io::stdout()).map_err(CliError::Io)?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(CliError::Io)?;
    Ok(line.trim().to_string())
}

pub fn prompt_password_required(label: &str) -> Result<String, CliError> {
    prompt_password(label).map_err(CliError::Io)
}

pub fn prompt_password_keep(label: &str) -> Result<Option<String>, CliError> {
    let value = prompt_line(label)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

pub fn prompt_optional_embedded_totp() -> Result<Option<EmbeddedTotp>, CliError> {
    if !confirm("Add TOTP for this entry? [y/N]: ")? {
        return Ok(None);
    }
    let seed = prompt_password("TOTP seed (base32): ").map_err(CliError::Io)?;
    let seed = seed.trim();
    if seed.is_empty() {
        return Err(CliError::Config("TOTP seed cannot be empty".into()));
    }
    Ok(Some(default_embedded_totp(seed)))
}

pub fn prompt_totp_edit(
    existing: Option<&EmbeddedTotp>,
) -> Result<Option<Option<EmbeddedTotp>>, CliError> {
    if existing.is_some() && confirm("Remove embedded TOTP? [y/N]: ")? {
        return Ok(Some(None));
    }
    if confirm("Set or replace embedded TOTP? [y/N]: ")? {
        let seed = prompt_password("TOTP seed (base32): ").map_err(CliError::Io)?;
        let seed = seed.trim();
        if seed.is_empty() {
            return Err(CliError::Config("TOTP seed cannot be empty".into()));
        }
        return Ok(Some(Some(default_embedded_totp(seed))));
    }
    Ok(None)
}

pub fn prompt_notes(label: &str) -> Result<String, CliError> {
    prompt_line(label)
}

pub fn prompt_extra_fields() -> Result<Vec<ExtraField>, CliError> {
    let mut fields = Vec::new();
    while confirm("Add an extra field? [y/N]: ")? {
        let key = prompt_line("  Field name: ")?;
        if key.is_empty() {
            continue;
        }
        let value = prompt_line("  Field value: ")?;
        fields.push(ExtraField { key, value });
    }
    Ok(fields)
}

pub fn prompt_extra_fields_edit(
    _existing: &[ExtraField],
) -> Result<Option<Vec<ExtraField>>, CliError> {
    if !confirm("Replace all extra fields? [y/N]: ")? {
        return Ok(None);
    }
    Ok(Some(prompt_extra_fields()?))
}
