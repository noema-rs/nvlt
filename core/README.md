# core

Cryptographic foundation for **nvlt**: the password-over-key Argon2id KDF chain, age X25519 identity handling, `lock` → salt (HKDF), `age` encrypt/decrypt, and TOTP helpers for site seeds.

Public entry points live in the `vault` module (re-exported from the crate root).
