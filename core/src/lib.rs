//! Vault core cryptographic engine.
#![forbid(unsafe_code)]

mod crypto;
mod error;
mod kdf;
mod lock;
mod secrets;
mod totp;
pub mod vault;

pub use error::Error;
pub use kdf::KdfParams;
pub use lock::salt_from_lock;
pub use vault::{decrypt, derive_key, derive_wrap_key, encrypt, generate_totp, verify_totp};
