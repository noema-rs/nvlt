use crate::error::CliError;

/// Parses `30s`, `10m`, `2h`, or plain seconds.
pub fn parse_duration(s: &str) -> Result<u64, CliError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(CliError::Config("duration cannot be empty".into()));
    }
    if let Some(num) = s.strip_suffix('s') {
        return num
            .parse()
            .map_err(|_| CliError::Config(format!("invalid duration: {s}")));
    }
    if let Some(num) = s.strip_suffix('m') {
        return num
            .parse::<u64>()
            .map(|n| n.saturating_mul(60))
            .map_err(|_| CliError::Config(format!("invalid duration: {s}")));
    }
    if let Some(num) = s.strip_suffix('h') {
        return num
            .parse::<u64>()
            .map(|n| n.saturating_mul(3600))
            .map_err(|_| CliError::Config(format!("invalid duration: {s}")));
    }
    s.parse()
        .map_err(|_| CliError::Config(format!("invalid duration: {s}")))
}
