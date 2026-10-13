## Why

Some services use 2FA without stored passwords; standalone TOTP entries live in `totp.age`. Spec: `openspec/specs/vault-totp/spec.md`.

## What Changes

- Add `totp/` crate (distinct from `vault_core` totp helpers): CRUD for standalone entries, code generation, QR export/import stubs.

## Capabilities

_(Main spec only.)_

## Impact

- Workspace member `totp`; depends on `core` and `totp-rs`.
