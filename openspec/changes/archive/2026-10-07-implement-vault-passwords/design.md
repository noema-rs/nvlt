## Context

`vault_core` provides derive/encrypt/decrypt. This crate owns the passwords JSON schema and merge logic for `pass.age`.

## Goals / Non-Goals

**Goals:** Typed `Entry` model, `(domain, username)` index, load/save encrypted blob, confirmation hooks as pure prompts (no stdin in lib).

**Non-Goals:** CLI, unlock flow, TOTP code display (uses core + entry seed at CLI layer).

## Decisions

- Store entire vault passwords file as one encrypted JSON document (per INIT).
- Timestamps in UTC RFC3339.
- Duplicate `(domain, username)` returns error on add.

## Risks / Trade-offs

- Large `pass.age` rewrites on every edit — acceptable for v1; split files later if needed.
