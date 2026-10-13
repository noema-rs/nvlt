use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use secrecy::{ExposeSecret, SecretString};

use crate::agent::paths::{agent_dir, pid_path, socket_path};
use crate::agent::protocol::{Request, Response};
use crate::error::CliError;

struct Session {
    vault_root: PathBuf,
    data_key: SecretString,
    ttl: Duration,
    expires_at: SystemTime,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn now() -> SystemTime {
    SystemTime::now()
}

fn touch(session: &mut Session) {
    session.expires_at = now() + session.ttl;
}

fn is_active(session: &Session) -> bool {
    now() < session.expires_at
}

fn handle(req: Request) -> Response {
    let mut guard = SESSION.lock().expect("agent session lock");
    match req {
        Request::Ping => Response::Pong,
        Request::Status => {
            if let Some(s) = guard.as_ref() {
                if is_active(s) {
                    let remaining = s
                        .expires_at
                        .duration_since(now())
                        .unwrap_or_default()
                        .as_secs();
                    return Response::Status {
                        active: true,
                        vault_root: Some(s.vault_root.to_string_lossy().into_owned()),
                        expires_in_secs: Some(remaining),
                    };
                }
                *guard = None;
            }
            Response::Status {
                active: false,
                vault_root: None,
                expires_in_secs: None,
            }
        }
        Request::Store {
            vault_root,
            data_key_b64,
            ttl_secs,
        } => {
            let bytes = match STANDARD.decode(data_key_b64) {
                Ok(b) => b,
                Err(_) => {
                    return Response::Error {
                        message: "invalid key encoding".into(),
                    }
                }
            };
            let ttl = Duration::from_secs(ttl_secs.max(1));
            let session = Session {
                vault_root: PathBuf::from(vault_root),
                data_key: SecretString::new(String::from_utf8_lossy(&bytes).into_owned()),
                ttl,
                expires_at: now() + ttl,
            };
            *guard = Some(session);
            Response::Ok
        }
        Request::GetDataKey { vault_root } => {
            let Some(session) = guard.as_mut() else {
                return Response::Error {
                    message: "no session".into(),
                };
            };
            if !is_active(session) {
                *guard = None;
                return Response::Error {
                    message: "no session".into(),
                };
            }
            if session.vault_root.as_os_str() != std::path::Path::new(&vault_root).as_os_str() {
                return Response::Error {
                    message: "session is for a different vault path".into(),
                };
            }
            touch(session);
            Response::DataKey {
                data_key_b64: STANDARD.encode(session.data_key.expose_secret().as_bytes()),
            }
        }
        Request::Lock => {
            *guard = None;
            Response::Ok
        }
    }
}

fn serve(mut stream: UnixStream) -> std::io::Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    let req: Request = serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let resp = handle(req);
    let payload = serde_json::to_vec(&resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let resp_len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&resp_len)?;
    stream.write_all(&payload)?;
    Ok(())
}

pub fn run_agent() -> Result<(), CliError> {
    let dir = agent_dir();
    fs::create_dir_all(&dir)?;
    crate::config::set_private_dir_permissions(&dir)?;
    let sock = socket_path();
    if sock.exists() {
        let _ = fs::remove_file(&sock);
    }
    let listener = UnixListener::bind(&sock).map_err(CliError::Io)?;
    crate::config::set_private_file_permissions(&sock)?;
    fs::write(pid_path(), std::process::id().to_string().as_bytes())?;
    for stream in listener.incoming().flatten() {
        let _ = serve(stream);
    }
    Ok(())
}
