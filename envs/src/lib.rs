//! Encrypted environment variable profiles.
#![forbid(unsafe_code)]

mod confirm;
mod error;
mod model;
mod profile;

pub use confirm::{
    remove_profile_confirmation, unset_confirmation, RemoveProfileConfirmation, UnsetConfirmation,
};
pub use error::Error;
pub use model::{export_line, EnvProfileDocument, EnvVar, ENV_PROFILE_VERSION};
pub use profile::{EnvVault, ProfileStore};
