## Why

Vault creation, backup, recovery, and rotation are security-critical flows. Spec: `openspec/specs/vault-lifecycle/spec.md`.

## What Changes

- `vault init`, `backup`, `recover`, `rotate` in CLI (or shared `vault/` lib module if preferred).
- On-disk layout: `salt.bin`, empty stores, dual keys (data vs backup).
- TOTP seed generation with RFC-compliant length; store primary seed per config (`os_keyring` / file / prompt).

## Capabilities

_(Main spec only.)_

## Impact

- Extends CLI; may add `vault/` internal module under `cli` or small `vault-store` crate.

## Non-Goals

- Phase 8 extras (multi-vault, import from other managers).
