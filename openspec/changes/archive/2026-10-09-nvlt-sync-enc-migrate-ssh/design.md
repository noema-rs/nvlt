## Context

See `proposal.md`. Today the CLI binary is `vault`, salt lives in `salt.bin`, primary seed uses `totp_seed_location`, backup seed is typed on backup/rotate, and there is no sync bundle. Crypto stack remains `core` (Argon2id + age + TOTP verify).

## Goals / Non-Goals

**Goals:**

- Single local secret envelope `nvlt.enc` for both TOTP seeds; password-based wrap; re-wrap after decrypt/use.
- Deterministic KDF salt from config `lock` via versioned HKDF (label `nvlt-lock-v1`, 16-byte output); **never persist salt bytes** on disk.
- Clear split: `init` (new) vs `init --migrate` (after `sync pull`, `lock` from config).
- `sync push` / `sync pull --path` → backup on push → pack config + `.age` → configurable **`host.age`** with **age scrypt passphrase + recipients (pubkey)**; plaintext **`host.pub`**.
- **Sync host passphrase** separate from vault master password.
- Pull confirms before overwriting local vault files.
- `nvlt reveal primary|backup`.
- `ssh` store + safe activate/deactivate under `~/.ssh`.
- Rename user-facing binary and paths to `nvlt` / `~/.nvlt`.

**Non-Goals:**

- Git integration, CI, or cloud upload.
- Encrypting `host.pub`.
- Using vault master password to encrypt or decrypt `host.age`.
- Cross-platform agent on non-Unix (unchanged limitation).
- Automatic migration from legacy `vault` / `salt.bin` installs.

## Decisions

### 1. `lock` → salt (memory only)

- **Choice**: `salt_bytes = HKDF-SHA256(ikm = UTF-8(lock), info = "nvlt-lock-v1", len = 16)` on every derive; no `salt.bin`.
- **Init**: generate random `lock` string stored only in `config.toml`.

### 2. `nvlt.enc` format

- **Choice**: versioned blob with password-wrapped primary and backup seeds; re-wrap after use (atomic rename). Uses **vault master password** only.

### 3. Init vs migrate

- **Choice**: `init` refuses when vault already initialized; `init --migrate` requires pulled or copied `config.toml` + `.age`, reads **`lock` from config**, prompts vault master password + seeds + TOTP codes only.

### 4. Sync pipeline

- **Push**: unlock vault → backup → stage config + all vault `.age` → build `host.age` as **nested age**: inner layer to X25519 pubkey, outer layer to sync host passphrase (age forbids scrypt + x25519 in a single file).
- **Pull**: confirm if vault root has files to replace → prompt sync host passphrase → decrypt outer then inner with local private key → write into vault root; never touch `nvlt.enc`.
- **Keys**: first push generates age keypair; private key gitignored locally; `host.pub` plaintext in sync dir.
- **Three secrets for full migration**: sync private key + sync host passphrase (open bundle) + vault master + TOTP (open vault + `init --migrate`).

### 5. Configurable sync filenames

- **Choice**: `[sync] host_file = "host.age"`, `pub_file = "host.pub"` in vault `config.toml`.

### 6. SSH module

- **Choice**: `ssh.age` JSON store by name; activate/deactivate under `~/.ssh` with tracked paths.

### 7. Binary rename

- **Choice**: Cargo bin `nvlt`; agent under `~/.cache/nvlt/agent` (or similar).

## Risks / Trade-offs

- **[Risk] User publishes `nvlt.enc`** → docs + push exclusion.
- **[Risk] Sync private key or sync host passphrase loss** → warn on first push; user backs up both offline.
- **[Risk] Pull overwrites local work** → mandatory confirmation when target files exist.
- **[Trade-off] Plaintext `host.pub` in git** → acceptable; opening `host.age` still needs private key + sync host passphrase.

## Migration Plan

1. Document greenfield nvlt setup; no auto-import from `~/.secrets`.
2. Archive OpenSpec change → update main specs + INIT.md.

## Open Questions

- None for sync crypto; implement age dual-mode per `age` crate API (passphrase + recipients on same file).
