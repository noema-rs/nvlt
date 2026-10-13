# core

Cryptographic foundation for **nvlt**: Argon2id key derivation, `lock` → salt (HKDF), `age` encrypt/decrypt, TOTP helpers, and password-wrap helpers for `nvlt.enc`.

Public entry points live in the `vault` module (re-exported from the crate root).
