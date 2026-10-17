use serde::{Deserialize, Serialize};

pub const ENV_PROFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvProfileDocument {
    pub version: u32,
    pub profile: String,
    pub vars: Vec<EnvVar>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

impl EnvProfileDocument {
    pub fn empty(profile: impl Into<String>) -> Self {
        Self {
            version: ENV_PROFILE_VERSION,
            profile: profile.into(),
            vars: Vec::new(),
        }
    }
}

fn shell_escape_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

/// Format a single `export KEY="value"` line with POSIX shell escaping.
pub fn export_line(key: &str, value: &str) -> String {
    format!("export {key}=\"{}\"", shell_escape_value(value))
}

/// Format a single `KEY="value"` dotenv line with the same escaping as export.
pub fn dotenv_line(key: &str, value: &str) -> String {
    format!("{key}=\"{}\"", shell_escape_value(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_escapes_special_chars() {
        let line = export_line("API_KEY", "sk-\"abc\"$HOME");
        assert_eq!(line, r#"export API_KEY="sk-\"abc\"\$HOME""#);
    }
}
