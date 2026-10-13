## Goals / Non-Goals

**Goals:** Implement flows exactly as INIT sequence diagrams; backup payload excludes primary seed; recover mints new primary seed.

**Non-Goals:** Core dumps hardening, disable coredump sysctl (document only).

## Decisions

- `salt.bin` 16 bytes, mode 600 on Unix.
- Backup re-encrypts snapshot with backup key after dual TOTP verify.
- Rotate re-encrypts all blobs; optional new password.

## Open points

- OS keyring: `keyring` crate vs secret-service / macOS — pick per target OS table in tasks.

## Risks / Trade-offs

- Recover replaces files — strong confirmations mandatory.
