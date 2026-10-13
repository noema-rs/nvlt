# passwords

Encrypted credential store for nvlt: JSON v2 entries in `pass.age`, keyed by `(domain, username)`.

Uses `vault_core` for age encrypt/decrypt. Confirmation prompt text for edit/remove lives here; stdin is handled by the CLI.
