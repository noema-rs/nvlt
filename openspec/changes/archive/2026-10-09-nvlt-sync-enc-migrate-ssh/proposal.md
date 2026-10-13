## Why

Primary and backup TOTP seeds are stored in plaintext on the host (keyring or file), backup flows re-prompt for seed text, and there is no portable public-git workflow. The product is being rebranded as **nvlt** with local encrypted seed storage, explicit migration, age-based sync bundles, and SSH key management.

## What Changes

- **BREAKING**: CLI binary renamed from `vault` to **`nvlt`**; default vault directory **`~/.nvlt`**; bootstrap config under **`~/.config/nvlt/`**.
- **BREAKING**: Replace `salt.bin` with config field **`lock`** (string) deterministically mapped to 16-byte KDF salt; remove `totp_seed_location` and plaintext seed files.
- **Local-only** **`nvlt.enc`**: encrypted primary and backup TOTP seeds (password-wrapped); re-wrap on read/use; never included in sync output.
- **`init`**: new vault only (generates `lock`, seeds, empty stores, `nvlt.enc`).
- **`init --migrate`**: after **pull**, uses **`lock` from config** (salt in memory only); user supplies master password, both seeds, TOTP codes; verify decrypt; write **`nvlt.enc`**.
- **`sync push` / `sync pull --path`**: push runs **backup** first, then packs into configurable **`host.age`** using age **sync host passphrase + public key** (distinct from vault master password); plaintext **`host.pub`**; pull confirms before overwriting local files; **do not** pack `nvlt.enc`.
- New **`ssh`** subsystem: register named keypairs from paths, list, activate/deactivate material under `~/.ssh`, optional open helper.
- **`nvlt reveal primary|backup`** with password + TOTP code for migration export.

## Capabilities

### New Capabilities

- `vault-sync`: Public-git sync bundle (`host.age`), sync key lifecycle, implicit backup before pack.
- `vault-ssh`: Encrypted SSH keypair registry keyed by name with activate/deactivate to `~/.ssh`.

### Modified Capabilities

- `vault-config`: `lock`-derived salt, `nvlt` paths, `nvlt.enc`; remove salt file and seed location modes.
- `vault-lifecycle`: `init` vs `init --migrate`, seed access via `nvlt.enc`, backup/rotate without seed prompts.
- `vault-cli`: `nvlt` binary, `sync`, `ssh`, updated lifecycle flags.
- `vault-core`: Deterministic `lock` → salt derivation (library contract).

## Impact

- `cli` crate: rename binary, paths, unlock/lifecycle/sync/ssh modules; agent socket paths may move under `nvlt`.
- `core`: lock salt derivation helper.
- New crate or module for sync tarball + optional `ssh` store (may mirror `totp` crate pattern).
- INIT.md, README, OpenSpec main specs updated on archive.
- No backward compatibility with `~/.secrets`, `salt.bin`, or `vault` binary name without manual migration.

## Non-Goals

- Automatic cloud upload or git commit from `nvlt sync`.
- Storing sync private keys inside the public sync directory.
- Replacing OpenSSH or managing `ssh-agent` beyond installing keys under `~/.ssh`.
- Hardware security modules or TPM in this change.
