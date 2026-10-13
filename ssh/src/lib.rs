#![forbid(unsafe_code)]

mod error;
mod model;
mod store;

pub use error::Error;
pub use model::{NewSshEntry, SshDocument, SshEntry, SSH_STORE_VERSION};
pub use store::SshStore;
