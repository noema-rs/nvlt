#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsetConfirmation {
    pub profile: String,
    pub key: String,
    pub prompt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveProfileConfirmation {
    pub profile: String,
    pub prompt: String,
}

pub fn unset_confirmation(profile: &str, key: &str) -> UnsetConfirmation {
    let prompt = format!(
        "⚠️  You are about to remove the variable \"{key}\" from profile \"{profile}\"\n\
            This action cannot be undone.\n\
         \n\
            Continue? [y/N]:"
    );
    UnsetConfirmation {
        profile: profile.to_string(),
        key: key.to_string(),
        prompt,
    }
}

pub fn remove_profile_confirmation(profile: &str) -> RemoveProfileConfirmation {
    let prompt = format!(
        "⚠️  You are about to delete the env profile: {profile}\n\
            All variables in this profile will be lost.\n\
            This action cannot be undone.\n\
         \n\
            Delete this profile? [y/N]:"
    );
    RemoveProfileConfirmation {
        profile: profile.to_string(),
        prompt,
    }
}
