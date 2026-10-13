//! Encrypted password vault (`pass.age`).
#![forbid(unsafe_code)]

mod confirm;
mod error;
mod model;
mod store;

pub use confirm::{edit_confirmation, remove_confirmation, EditConfirmation, RemoveConfirmation};
pub use error::Error;
pub use model::{
    default_embedded_totp, EmbeddedTotp, Entry, EntryUpdate, ExtraField, NewEntry,
    PasswordsDocument, TotpAlgorithm, TotpCode, PASSWORDS_FILE_VERSION,
};
pub use store::PasswordStore;
