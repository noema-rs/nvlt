use std::fs;
use blake3::Hasher;

use crate::error::CliError;

const DOMAIN: &[u8] = b"nvlt-device-v1";

/// Stable host fingerprint for binding local rate duplas and recovery bundles.
pub fn compute_device_id() -> Result<String, CliError> {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN);
    for part in platform_components()? {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn platform_components() -> Result<Vec<String>, CliError> {
    #[cfg(target_os = "linux")]
    {
        Ok(vec![
            read_optional_file("/etc/machine-id"),
            read_optional_file("/sys/class/dmi/id/product_uuid"),
            read_optional_file("/sys/class/dmi/id/board_serial"),
        ])
    }
    #[cfg(not(target_os = "linux"))]
    {
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown-host".into());
        Ok(vec![host])
    }
}

fn read_optional_file(path: &str) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn ensure_device_matches(stored: &str) -> Result<(), CliError> {
    let live = compute_device_id()?;
    if live == stored {
        Ok(())
    } else {
        Err(CliError::DeviceMismatch)
    }
}

pub fn read_stored_device_id(config: &crate::config::Config) -> Result<&str, CliError> {
    config
        .vault
        .device_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CliError::Config("missing device_id in config; re-init or renew rate limit".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_stable_within_process() {
        let a = compute_device_id().unwrap();
        let b = compute_device_id().unwrap();
        assert_eq!(a, b);
        assert!(a.len() >= 32);
    }
}
