# VERSION 2

Breaking redesign of the lock system, CLI layout, and key inventory.
All changes are breaking: existing v1 vaults get re-initialized from a snapshot.

## 1. New lock system

### What changes
- Unlock = **master password + private key path**. OTP/TOTP for **unlock** is removed
  (a seed stored on the machine the vault protects is not a second factor).
- The `nvlt totp` feature (standalone site seeds) is untouched — only auth OTP dies.
- **Never auto-discover the key.** Every unlock (and any feature that needs the key)
  prompts for the path like a password prompt, but the path is typed **visible/echoed**
  — the password stays hidden. Visible path = you see which USB key you pointed at.
- Session model unchanged: `nvlt unlock --for 10m` caches the data key in the agent;
  prompts happen only on first unlock.

### Security rules (non-negotiable)
- Key material must be part of the **KDF chain** (password layer wrapped over key
  layer, sequential) — password-only guessing must reveal nothing.
- Key custody: keep the key **off the machine** (USB/offline). If the key path is
  under the vault root or on the same filesystem as the vault → **hard warning** at unlock.
- Optional at-rest encryption of the key file with a **separate** passphrase
  (never the master password — that would be circular), decrypted in memory on use.
- Argon2 KDF params get bumped to **256 MiB (262144 KiB), t=4, p=4** — for the
  degraded on-disk-key configuration they are the only brake on offline guessing.

### Residual risks (what actually matters in v2)
1. **Session left unlocked too long** — an attacker at an unlocked terminal never
   hits any check. Mitigation: sensible agent TTL + sliding idle timeout; document it.
2. **Private key saved on disk unencrypted** — key + ciphertext in hand = vault open
   (modulo password). Mitigation: hard warning at unlock + optional passphrase wrap.

Device binding protects **neither** of these — removed (section 2).

### Key inventory: 4 keys + 2 passwords → 3 keys + 1 password
| Key | Role | Custody |
|---|---|---|
| sync key | git snapshot transport | online (`.nvlt-sync/`) |
| main unlock key | daily unlock | off machine; if on disk: warn + optional passphrase wrap |
| backup unlock key | `recover` / key loss | **strictly offline** |

1 master password. The old 2nd password was the **recovery-bundle passphrase**
(confirmed in `cli/src/lifecycle.rs`); it disappears with rate limit.

## 2. Rate limit and device binding removed

**Rate limit:** in v2 the slots would carry no factor (the key lives outside the
machine), so the system has no job left: without the key no attempt can succeed, and a
disk-level attacker bypasses the app counter entirely.

**Device binding:** with the rate-limit signing key gone, `device_id` is just a
plaintext config line — anyone rewrites it in seconds. A protocol-aware attacker
bypasses it; it protects neither residual risk above; wipe-on-mismatch self-DoSes
legit hardware changes (OS reinstall, board swap, hostname change on Win/macOS); and
it fights the snapshot workflow itself — importing `host.age` on a new machine *is*
the point of `init --from-snapshot`, so a device check has no place here. Not a
security boundary — deleted rather than kept as decoration.

Deletes:
- `rate_limit.rs`, `rate_limit_cmd.rs`, `RateLimit` command, `rate/` (30 files)
- `device.rs`, `config.vault.device_id`, all `guard_device` calls, wipe-on-mismatch
- the 4th key (rate-limit key), the recovery bundle, `rate-limit renew`
- rate config fields; specs `vault-rate-limit` + `vault-device-bind` archived

Replaced by: key-in-KDF chain (real defense) + Argon2 cost (degraded-config brake)
+ key-custody warnings.

## 3. CLI changes

- Lifecycle/admin under `system`:
  `nvlt system init | status | backup | recover | rotate | snapshot | panic | config`
- Data commands stay top level: `pass`, `env`, `files`, `totp`, `ssh`, `unlock`, `lock`
  (`agent` stays hidden)
- **Delete `reveal`** — unused (`Reveal` variant, `RevealCmd`, `run_reveal`, `reveal.rs`)
- No `help` subcommand — `--help` on every command; bare `nvlt` prints the command list
- `rate-limit` subcommand gone (section 2)

## 4. Lifecycle flows

- `init` — generates main + backup keys, prints offline-storage instructions for the
  backup key; no rate duplas, no recovery bundle, no device registration
- `backup` — authorized with the **backup key** (was: backup authenticator code)
- `recover` — backup key + master password; can issue a new main key
- `rotate` — new master password and/or new main/backup keys; re-encrypt all stores
- `panic` — stays: deletes the local encrypted vault files (the `.age` files under the
  vault directory); recovery = git snapshot + `init --from-snapshot`
- Migration: v1 vaults → re-init from snapshot (breaking, no in-place upgrade)

## 5. `age` wrapper (separate change, no lock dependency)

- `nvlt age encrypt|decrypt|identity` — thin passthrough over the `age` crate we
  already use (snapshot, ssh.age, files). Never reimplement age in our program.

## Questions → decisions

- age wrapper: yes, as a **separate** feature — ✅
- TOTP → private keys, two keys main+backup: ✅ (backup strictly offline)
- rate limit: **dropped** — ✅
- device id / device binding: **dropped** (conflicts with snapshot import on new
  machines anyway) — ✅
- key inventory: reduced to 3 keys / 1 password — ✅
- panic: stays, narrowed to deleting local `.age` files — ✅
- snapshot under `system`: stays — ✅
- key format: **age X25519 identity** (`AGE-SECRET-KEY-1…`, public `age1…`) — ✅
- Argon2 bump: 256 MiB, t=4, p=4 — ✅
- old 2nd password = recovery-bundle passphrase; removed with rate limit — ✅

## Open

_None — all v1 open items resolved above. OpenSpec specs + config updated to v2._
