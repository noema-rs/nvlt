## Why

Users need to encrypt arbitrary files into the vault store. Spec: `openspec/specs/vault-files/spec.md`.

## What Changes

- Add `files/` crate: raw-byte encrypt/decrypt, vault `files/` directory layout, list/remove metadata.

## Capabilities

_(Main spec only.)_

## Impact

- Workspace member `files`; depends on `core`.
