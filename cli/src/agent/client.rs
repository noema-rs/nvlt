use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use secrecy::{ExposeSecret, SecretString};

use crate::agent::paths::socket_path;
use crate::agent::protocol::{Request, Response};
use crate::error::CliError;

enum ConnectError {
    Unavailable,
    Io(std::io::Error),
}

fn connect() -> Result<UnixStream, ConnectError> {
    match UnixStream::connect(socket_path()) {
        Ok(stream) => Ok(stream),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::NotFound
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::AddrNotAvailable
                    | ErrorKind::PermissionDenied
            ) =>
        {
            Err(ConnectError::Unavailable)
        }
        Err(e) => Err(ConnectError::Io(e)),
    }
}

fn exchange(req: &Request) -> Result<Response, CliError> {
    let mut stream = match connect() {
        Ok(s) => s,
        Err(ConnectError::Unavailable) => {
            return Err(CliError::AgentUnavailable);
        }
        Err(ConnectError::Io(e)) => return Err(CliError::Io(e)),
    };
    let payload = serde_json::to_vec(req)?;
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(CliError::Io)?;
    stream.write_all(&payload).map_err(CliError::Io)?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(CliError::Io)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).map_err(CliError::Io)?;
    serde_json::from_slice(&buf).map_err(|e| CliError::Config(e.to_string()))
}

pub fn ping() -> Result<(), CliError> {
    match exchange(&Request::Ping)? {
        Response::Pong => Ok(()),
        Response::Error { message } => Err(CliError::Config(message)),
        _ => Err(CliError::Config("unexpected agent response".into())),
    }
}

pub fn store_session(
    vault_root: &Path,
    data_key: &SecretString,
    ttl_secs: u64,
) -> Result<(), CliError> {
    let data_key_b64 = STANDARD.encode(data_key.expose_secret().as_bytes());
    match exchange(&Request::Store {
        vault_root: vault_root.to_string_lossy().into_owned(),
        data_key_b64,
        ttl_secs,
    })? {
        Response::Ok => Ok(()),
        Response::Error { message } => Err(CliError::Config(message)),
        _ => Err(CliError::Config("unexpected agent response".into())),
    }
}

pub fn get_data_key(vault_root: &Path) -> Result<Option<SecretString>, CliError> {
    let resp = match exchange(&Request::GetDataKey {
        vault_root: vault_root.to_string_lossy().into_owned(),
    }) {
        Ok(r) => r,
        Err(CliError::AgentUnavailable) => return Ok(None),
        Err(e) => return Err(e),
    };
    match resp {
        Response::DataKey { data_key_b64 } => {
            let bytes = STANDARD
                .decode(data_key_b64)
                .map_err(|_| CliError::Config("invalid agent key payload".into()))?;
            Ok(Some(SecretString::new(
                String::from_utf8_lossy(&bytes).into_owned(),
            )))
        }
        Response::Error { message } if message == "no session" => Ok(None),
        Response::Error { message } => Err(CliError::Config(message)),
        _ => Ok(None),
    }
}

pub fn lock() -> Result<(), CliError> {
    match exchange(&Request::Lock) {
        Err(CliError::AgentUnavailable) => Ok(()),
        Err(e) => Err(e),
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error { message }) => Err(CliError::Config(message)),
        Ok(_) => Ok(()),
    }
}

pub fn agent_status() -> Result<Option<(String, u64)>, CliError> {
    let resp = match exchange(&Request::Status) {
        Ok(r) => r,
        Err(CliError::AgentUnavailable) => return Ok(None),
        Err(e) => return Err(e),
    };
    match resp {
        Response::Status {
            active: true,
            vault_root: Some(root),
            expires_in_secs: Some(secs),
        } => Ok(Some((root, secs))),
        Response::Status { active: false, .. } => Ok(None),
        Response::Error { message } => Err(CliError::Config(message)),
        _ => Ok(None),
    }
}
