## Context

Greenfield Rust workspace. INIT.md defines module boundaries and dependencies. No application code exists yet. This change delivers only the `core` crate specified in `openspec/specs/vault-core/spec.md`.

## Goals / Non-Goals

**Goals:**

- Cargo workspace with `core` as the first member crate.
- Modules: `crypto`, `kdf`, `totp`, `secrets`, `vault` (public facade), `error`.
- Public API matching INIT.md: `derive_key`, `encrypt`, `decrypt`, `verify_totp`, `generate_totp`.
- Argon2id with parameter struct (defaults aligned to config spec: 64 MiB, t=3, p=4).
- age encrypt/decrypt using derived 32-byte keys wrapped in `SecretString`.
- TOTP via `totp-rs` (SHA1, 6 digits, 30s default unless caller overrides).
- `thiserror` in `core`; no miette in this crate (CLI comes later).

**Non-Goals:**

- Disk layout, `vault init`, CLI binary, OS keyring, backup/recover flows.
- Subsystem crates (`passwords`, `envs`, `files`, `totp`).
- Integration tests against real vault files (unit/crypto tests only).

## Decisions

1. **KDF input encoding** — Concatenate password and seed as UTF-8 bytes in a fixed order (`password || seed`) as INIT.md states. Salt is raw 16 bytes from file in later phases; for `core`, salt is caller-provided slice.

2. **age usage** — Use the official `age` crate with X25519/scrypt as provided; our 32-byte Argon2 output is the symmetric secret for age's recipient-less encrypt API appropriate for file-style payloads (document exact age API in implementation).

3. **Secrets** — Re-export or thin-wrap `secrecy::SecretString`; ensure `zeroize` on sensitive byte buffers where not already handled by `secrecy`.

4. **TOTP verification window** — Accept current time step only for unlock-style verification unless tests require ±1 step skew; document choice in code if skew is added.

5. **Testing** — Focus on deterministic KDF vectors, encrypt round-trip, decrypt failure on wrong key, TOTP valid/invalid with fixed clock or test helper. Property tests optional later.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| age API mismatch with 32-byte raw keys | Spike in `crypto.rs` first task; adjust to age's expected key format early |
| TOTP clock skew in CI | Use totp-rs test features or inject time in unit tests |
| Argon2 params too slow for tests | Use reduced params only in `#[cfg(test)]` helpers, not in production defaults |
