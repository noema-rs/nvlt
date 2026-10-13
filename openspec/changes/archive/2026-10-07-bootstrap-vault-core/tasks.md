## 1. Workspace skeleton

- [x] 1.1 Add root `Cargo.toml` workspace with `core` member and shared metadata (edition 2021, resolver 2)
- [x] 1.2 Create `core/Cargo.toml` with dependencies from INIT.md (`age`, `secrecy`, `argon2`, `totp-rs`, `rand`, `serde`, `serde_json`, `thiserror`, `zeroize`)
- [x] 1.3 Add `core/src/lib.rs` re-exporting the public API module `vault`

## 2. Errors and secrets

- [x] 2.1 Implement `error.rs` with `thiserror` variants for KDF, crypto, and TOTP failures (no secret leakage in `Display`)
- [x] 2.2 Implement `secrets.rs` helpers around `SecretString` and zeroization patterns used by kdf/crypto

## 3. KDF and crypto

- [x] 3.1 Implement `kdf.rs`: Argon2id derive to 32 bytes with configurable `Params` and default costs from spec
- [x] 3.2 Implement `crypto.rs`: encrypt/decrypt bytes via age using derived key material
- [x] 3.3 Wire `vault.rs` public functions `derive_key`, `encrypt`, `decrypt`

## 4. TOTP

- [x] 4.1 Implement `totp.rs`: `verify_totp` and `generate_totp` using seed + standard defaults
- [x] 4.2 Expose TOTP functions through `vault.rs`

## 5. Tests (crypto-heavy)

- [x] 5.1 KDF: deterministic output for fixed inputs; different keys when password or seed changes
- [x] 5.2 Crypto: encrypt/decrypt round-trip; failure with wrong key
- [x] 5.3 TOTP: valid code passes; invalid code fails
- [x] 5.4 Run `cargo test`, `cargo clippy`, and `cargo fmt` clean on workspace
