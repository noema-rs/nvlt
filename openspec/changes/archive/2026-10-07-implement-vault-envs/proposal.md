## Why

Developers need per-project env profiles encrypted on disk with granular key operations. Spec: `openspec/specs/vault-envs/spec.md`.

## What Changes

- Add `envs/` crate: one encrypted JSON file per profile under `envs/<name>.age`.
- API for list profiles, list keys, get/set/unset, add/remove profile, export as shell lines.

## Capabilities

_(Main spec only; skip_specs.)_

## Impact

- Workspace member `envs`; depends on `core`.
