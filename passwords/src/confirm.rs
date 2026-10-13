//! User-facing confirmation copy for destructive password operations (English).

/// Details shown before editing an existing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditConfirmation {
    pub domain: String,
    pub username: String,
    pub prompt: String,
}

/// Details shown before removing an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveConfirmation {
    pub domain: String,
    pub username: String,
    pub prompt: String,
}

/// Build the edit confirmation message for `(domain, username)`.
pub fn edit_confirmation(domain: &str, username: &str) -> EditConfirmation {
    let prompt = format!(
        "⚠️  You are about to modify the entry:\n\
            Domain:   {domain}\n\
            Username: {username}\n\
         \n\
            The current password, TOTP seed, and fields will be overwritten.\n\
         \n\
            Continue? [y/N]:"
    );
    EditConfirmation {
        domain: domain.to_string(),
        username: username.to_string(),
        prompt,
    }
}

/// Build the remove confirmation message for `(domain, username)`.
pub fn remove_confirmation(domain: &str, username: &str) -> RemoveConfirmation {
    let prompt = format!(
        "⚠️  You are about to delete the entry:\n\
            Domain:   {domain}\n\
            Username: {username}\n\
            This action cannot be undone.\n\
         \n\
            Delete this entry? [y/N]:"
    );
    RemoveConfirmation {
        domain: domain.to_string(),
        username: username.to_string(),
        prompt,
    }
}
