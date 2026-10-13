## Why

When the user believes the local machine or vault tree is compromised, they need an immediate, documented way to destroy operational secrets on disk without relying on rate-limit exhaustion. Recovery is expected via git snapshot and offline bundle elsewhere.

## What Changes

- Add **`nvlt panic`**: strong confirmation, optional master password verification, wipe local operational vault files, clear agent session, reset vault-local config initialization fields.
- Reuse the same path list as device-mismatch wipe (`pass.age`, stores, `rate/`, legacy `nvlt.enc`, etc.).
- Does **not** delete the user's snapshot git repo or offline recovery bundle.

## Capabilities

### New Capabilities

- `vault-panic`: emergency local destruction command and UX.

### Modified Capabilities

- `vault-cli`: register `panic` top-level subcommand.
- `vault-lifecycle`: document panic vs recover/from-snapshot recovery paths.

## Impact

- `cli/src/panic.rs` (or extend `wipe.rs`), `main.rs`, `lifecycle.rs` help text, INIT.md / README brief mention.

## Non-goals

- Secure multi-pass overwrite of entire disk.
- Remote wipe or cloud integration.
- Panic on remote machines via API.
