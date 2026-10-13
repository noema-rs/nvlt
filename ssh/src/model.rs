use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const SSH_STORE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDocument {
    pub version: u32,
    pub entries: Vec<SshEntry>,
}

impl SshDocument {
    pub fn empty() -> Self {
        Self {
            version: SSH_STORE_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshEntry {
    pub name: String,
    pub private_pem: String,
    pub public_openssh: String,
    pub host: Option<String>,
    pub user: Option<String>,
    pub installed_paths: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewSshEntry {
    pub name: String,
    pub private_pem: String,
    pub public_openssh: String,
    pub host: Option<String>,
    pub user: Option<String>,
}

impl NewSshEntry {
    pub fn into_entry(self, now: DateTime<Utc>) -> SshEntry {
        SshEntry {
            name: self.name,
            private_pem: self.private_pem,
            public_openssh: self.public_openssh,
            host: self.host,
            user: self.user,
            installed_paths: Vec::new(),
            created_at: now,
        }
    }
}
