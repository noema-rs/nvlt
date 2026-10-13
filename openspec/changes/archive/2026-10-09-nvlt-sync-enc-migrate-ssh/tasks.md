## 1. Core and config

- [x] 1.1 Implement `lock` → 16-byte salt (HKDF-SHA256, `nvlt-lock-v1`) in `core` with unit tests
- [x] 1.2 Extend config model: default path `~/.nvlt`, bootstrap `~/.config/nvlt`, `lock` field; remove `totp_seed_location` and `salt_file` usage
- [x] 1.3 Update `VaultLayout` for `nvlt.enc`; drop `salt.bin` and legacy primary seed file paths

## 2. nvlt.enc

- [x] 2.1 Define `nvlt.enc` serialize/parse, password wrap/unwrap for primary and backup seeds
- [x] 2.2 Implement re-wrap on read path shared by unlock, backup, rotate, migrate
- [x] 2.3 Integration tests: round-trip, wrong password fails, re-wrap changes ciphertext but same seeds

## 3. Lifecycle

- [x] 3.1 Refactor `init` for new vault: generate `lock`, seeds, verify TOTP, write stores and `nvlt.enc`
- [x] 3.2 Implement `init --migrate`: read `lock` from config, seeds, codes, proof-decrypt, write `nvlt.enc` only when valid
- [x] 3.3 Update backup/rotate/recover to load seeds from `nvlt.enc` (backup code prompt, no seed text)
- [x] 3.4 Add `nvlt reveal primary` and `nvlt reveal backup` per spec
- [x] 3.5 Update lifecycle integration tests for new layout

## 4. CLI rename and agent

- [x] 4.1 Rename binary to `nvlt`; update clap names, agent paths, error strings (English)
- [x] 4.2 Adjust unlock/session flow for `lock`-derived salt and `nvlt.enc`
- [x] 4.3 Update `status`, config commands, and docs references

## 5. Sync

- [x] 5.1 Config keys for sync host/pub basenames; defaults `host.age` / `host.pub`
- [x] 5.2 Sync keypair generation, optional sync passphrase wrap for private key, plaintext pub in sync dir, gitignored private key
- [x] 5.3 `sync push`: backup; prompt sync host passphrase; pack into host archive (age passphrase + pubkey recipients); exclude `nvlt.enc`
- [x] 5.4 `sync pull`: confirm overwrite; prompt sync host passphrase; decrypt with private key + passphrase into vault root; do not touch `nvlt.enc`
- [x] 5.5 Tests: push/pull round-trip; manifest excludes local secrets

## 6. SSH

- [x] 6.1 Add `ssh` crate (or module) with encrypted `ssh.age` document keyed by name
- [x] 6.2 CLI: register (path), list, remove with confirmation
- [x] 6.3 CLI: activate/deactivate with tracked paths under `~/.ssh`
- [x] 6.4 Optional open helper when host/user metadata present
- [x] 6.5 Tests for duplicate name, activate/deactivate idempotency

## 7. Documentation and validation

- [x] 7.1 Update INIT.md for nvlt paths, lock, init/migrate, sync, ssh, git workflow
- [x] 7.2 Run `cargo test`, `cargo clippy --workspace -- -D warnings`, `openspec validate nvlt-sync-enc-migrate-ssh --strict`
- [x] 7.3 Archive change and sync main specs when implementation complete
