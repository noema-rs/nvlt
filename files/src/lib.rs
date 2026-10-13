//! Encrypted file blob store.
#![forbid(unsafe_code)]

mod error;
mod vault;

pub use error::Error;
pub use vault::{FileVault, OverwritePolicy};
