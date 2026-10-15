//! Vault core cryptographic engine.
#![forbid(unsafe_code)]

mod crypto;
mod error;
mod identity;
mod kdf;
mod lock;
mod totp;
pub mod vault;

pub use error::Error;
pub use kdf::KdfParams;
pub use lock::salt_from_lock;
pub use vault::{
    decrypt, derive_key, encrypt, generate_identity, generate_totp, is_identity, load_identity,
    public_key, verify_totp, wrap_identity,
};
