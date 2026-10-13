use std::io::{self, Write};

use crate::error::CliError;

pub fn confirm(prompt: &str) -> Result<bool, CliError> {
    print!("{prompt}");
    io::stdout().flush().map_err(CliError::Io)?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(CliError::Io)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(matches!(answer.as_str(), "y" | "yes"))
}

pub fn confirm_or_cancel(prompt: &str) -> Result<(), CliError> {
    if confirm(prompt)? {
        Ok(())
    } else {
        Err(CliError::Cancelled)
    }
}
