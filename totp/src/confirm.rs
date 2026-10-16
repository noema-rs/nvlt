#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveConfirmation {
    pub site: String,
    pub account: String,
    pub prompt: String,
}

pub fn remove_confirmation(site: &str, account: &str) -> RemoveConfirmation {
    let prompt = format!(
        "⚠️  You are about to delete the TOTP entry for: {site} ({account})\n\
            You will lose access to the 2FA codes for this service.\n\
            This action cannot be undone.\n\
         \n\
            Delete this entry? [y/N]:"
    );
    RemoveConfirmation {
        site: site.to_string(),
        account: account.to_string(),
        prompt,
    }
}
