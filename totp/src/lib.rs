//! Standalone TOTP seed vault.
#![forbid(unsafe_code)]

mod confirm;
mod error;
mod model;
mod qr;
mod store;

pub use confirm::{remove_confirmation, RemoveConfirmation};
pub use error::Error;
pub use model::{
    default_entry, parse_otpauth_uri, prepare_seed, NewTotpEntry, TotpAlgorithm, TotpCode,
    TotpDocument, TotpEntry, TOTP_STORE_VERSION,
};
pub use qr::{qr_ascii, write_qr_png};
pub use store::TotpStore;
