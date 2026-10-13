## Goals / Non-Goals

**Goals:** Stream file bytes through age via core; store ciphertext by basename; list names in store.

**Non-Goals:** CLI confirmations (cli change); compression.

## Decisions

- No JSON wrapper — ciphertext bytes only (INIT).
- Collision policy: overwrite only after CLI confirmation (library returns `AlreadyExists` unless `force` flag).

## Risks / Trade-offs

- Large files load into memory in v1 — document limit; streaming later.
