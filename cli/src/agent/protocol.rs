use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ping,
    Status,
    Store {
        vault_root: String,
        data_key_b64: String,
        ttl_secs: u64,
    },
    GetDataKey {
        vault_root: String,
    },
    Lock,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Pong,
    Status {
        active: bool,
        vault_root: Option<String>,
        expires_in_secs: Option<u64>,
    },
    DataKey {
        data_key_b64: String,
    },
    Error {
        message: String,
    },
}
