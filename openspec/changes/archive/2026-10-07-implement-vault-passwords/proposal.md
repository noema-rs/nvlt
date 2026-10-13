## Why

Users need encrypted credential storage keyed by site and username before the CLI can expose `vault pass` commands. Spec: `openspec/specs/vault-passwords/spec.md`.

## What Changes

- Add `passwords/` crate with JSON v2 model, in-memory store API, and `pass.age` encrypt/decrypt via `vault_core`.
- Implement search/list/get/add/edit/remove with confirmation on edit/remove.
- Support embedded TOTP metadata and flexible `fields`.

## Capabilities

### New Capabilities

_(Requirements in main spec; no delta.)_

### Modified Capabilities

_(none)_

## Impact

- New workspace member `passwords`; depends on `core`.
- No CLI yet (wired in `implement-vault-cli`).
