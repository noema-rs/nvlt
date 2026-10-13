use std::path::PathBuf;

use directories::ProjectDirs;

pub fn agent_dir() -> PathBuf {
    ProjectDirs::from("", "", "nvlt")
        .map(|d| d.cache_dir().join("agent"))
        .unwrap_or_else(|| PathBuf::from(".vault-agent"))
}

pub fn socket_path() -> PathBuf {
    agent_dir().join("agent.sock")
}

pub fn pid_path() -> PathBuf {
    agent_dir().join("agent.pid")
}
