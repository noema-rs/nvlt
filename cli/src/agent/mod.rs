#[cfg(unix)]
mod client;
#[cfg(unix)]
mod duration;
#[cfg(unix)]
mod paths;
#[cfg(unix)]
mod protocol;
#[cfg(unix)]
mod server;

#[cfg(unix)]
pub use client::{agent_status, lock, store_session};
#[cfg(unix)]
pub use duration::parse_duration;
#[cfg(unix)]
pub use server::run_agent;

#[cfg(unix)]
pub fn ensure_running() -> Result<(), crate::error::CliError> {
    prepare_agent_dir()?;
    match client::ping() {
        Ok(()) => return Ok(()),
        Err(crate::error::CliError::AgentUnavailable) => {}
        Err(e) => return Err(e),
    }
    let exe = std::env::current_exe().map_err(crate::error::CliError::Io)?;
    std::process::Command::new(exe)
        .arg("agent")
        .arg("run")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(crate::error::CliError::Io)?;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if client::ping().is_ok() {
            return Ok(());
        }
    }
    Err(crate::error::CliError::Config(
        "vault agent failed to start (try: rm -rf ~/.cache/vault/agent and run unlock again)".into(),
    ))
}

#[cfg(unix)]
fn prepare_agent_dir() -> Result<(), crate::error::CliError> {
    use std::fs;
    let dir = paths::agent_dir();
    if dir.is_dir() {
        crate::config::set_private_dir_permissions(&dir)?;
    } else {
        fs::create_dir_all(&dir)?;
        crate::config::set_private_dir_permissions(&dir)?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn try_data_key(
    vault_root: &std::path::Path,
) -> Result<Option<secrecy::SecretString>, crate::error::CliError> {
    client::get_data_key(vault_root)
}

#[cfg(not(unix))]
pub fn ensure_running() -> Result<(), crate::error::CliError> {
    Err(crate::error::CliError::Config(
        "vault agent is only supported on Unix".into(),
    ))
}

#[cfg(not(unix))]
pub fn try_data_key(
    _vault_root: &std::path::Path,
) -> Result<Option<secrecy::SecretString>, crate::error::CliError> {
    Ok(None)
}

#[cfg(not(unix))]
pub fn store_session(
    _vault_root: &std::path::Path,
    _data_key: &secrecy::SecretString,
    _ttl_secs: u64,
) -> Result<(), crate::error::CliError> {
    Err(crate::error::CliError::Config(
        "vault agent is only supported on Unix".into(),
    ))
}

#[cfg(not(unix))]
pub fn lock() -> Result<(), crate::error::CliError> {
    Ok(())
}

#[cfg(not(unix))]
pub fn agent_status() -> Result<Option<(String, u64)>, crate::error::CliError> {
    Ok(None)
}

#[cfg(not(unix))]
pub fn parse_duration(_s: &str) -> Result<u64, crate::error::CliError> {
    Err(crate::error::CliError::Config(
        "vault agent is only supported on Unix".into(),
    ))
}

#[cfg(not(unix))]
pub fn run_agent() -> Result<(), crate::error::CliError> {
    Err(crate::error::CliError::Config(
        "vault agent is only supported on Unix".into(),
    ))
}
