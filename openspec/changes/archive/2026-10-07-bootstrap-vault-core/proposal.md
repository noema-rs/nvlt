## Why

Vault needs a shared cryptographic foundation before any subsystem (passwords, envs, files, TOTP) can persist data. Phase 1 from INIT.md delivers that foundation with test coverage strong enough to trust every later feature.

## What Changes

- Create the Cargo workspace root and the `core` crate skeleton described in INIT.md.
- Implement Argon2id key derivation with configurable parameters matching config defaults.
- Wrap `age` for encrypt/decrypt using derived 32-byte keys held as `SecretString`.
- Implement TOTP generation and verification against the primary seed (possession check, not key material from the rotating code).
- Expose the public `core` API: `derive_key`, `encrypt`, `decrypt`, `verify_totp`, `generate_totp`.
- Add typed errors and secret handling with zeroization.
- Add cryptographic unit tests (deterministic KDF, distinct keys, round-trip, wrong key, TOTP valid/invalid).

No CLI, vault init, or on-disk layout in this change — only the `core` library.

## Capabilities

### New Capabilities

_(Requirements already captured in `openspec/specs/vault-core/spec.md`; this change implements them without spec deltas.)_

### Modified Capabilities

_(none)_

## Impact

- New directories: workspace `Cargo.toml`, `core/` with modules `crypto`, `kdf`, `totp`, `secrets`, `vault`, `error`.
- Dependencies per INIT.md: `age`, `secrecy`, `argon2`, `totp-rs`, `rand`, `serde`, `serde_json`, `thiserror`, `zeroize`.
- Downstream crates (`passwords`, `envs`, `files`, `totp`, `cli`) remain unstarted until later changes.
