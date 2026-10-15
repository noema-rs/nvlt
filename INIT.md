# nvlt — Project documentation

## Overview

**nvlt** is a desktop secret manager written in Rust that uses **age** for encryption. It unlocks with a **master password plus a private key file** (an age X25519 identity kept off the machine) and exposes these subsystems:

1. **Passwords** — credential store by domain with multiple users and flexible fields.
2. **Envs** — environment variable manager with granular commands.
3. **Files** — encryption of arbitrary files.
4. **TOTP** — standalone TOTP seeds (for services without an associated login password).
5. **SSH** — keypairs registered by name; temporary activation under `~/.ssh`.

Vault data lives in `.age` files under `~/.nvlt` by default. The **unlock key** feeds the key layer of the KDF chain and is never stored under the vault root; the **backup unlock key** stays strictly offline. **nvlt does not persist credential plaintext on its own.**

This document describes **version 2**. v1 vaults (TOTP-composite key, `rate/` duplas, device binding) are re-initialized from a snapshot; there is no in-place upgrade. See `VERSION_2.md` for the redesign.

---

## Design philosophy

- **One vault, one password, two keys.** Day-to-day `.age` files are protected by a data key derived from the master password *over* the main unlock key; `backup.age` uses the backup unlock key.
- **The key is part of the KDF, not a decoration.** The key secret enters the Argon2id chain; without the key file the correct password reveals nothing.
- **Never auto-discover the key.** Every unlock prompts for the key path, typed **visibly**, like a password prompt — you see which USB key you pointed at. The password stays hidden.
- **Key custody is the design.** Keep the main key off the machine (USB/offline); keep the backup key strictly offline. If a key path is under the vault root or on the same filesystem as the vault, the CLI prints a hard warning.
- **Panic:** `nvlt system panic` is the intentional compromise response: confirm, type `PANIC`, verify the master password when `pass.age` exists, then wipe local `.age` stores and clear `lock` in config. Git snapshot repos outside the vault root and your key files are untouched. Restore with `snapshot import` or an existing clone, then `nvlt system init --from-snapshot --path <repo>`.
- **Public snapshots:** `snapshot export` packs `config.toml` + `.age` (including `ssh.age` when present) into `host.age` (sync host passphrase + pubkey). Does **not** include key files or sync private key. Future: `snapshot sync` for diff/merge.
- **Separation by files, not by passwords.** Each env profile, each file under `files/`, each vault entry has its own encrypted file.
- **The vault does not persist plaintext by itself.** Export to stdout or redirection to a file is the user’s responsibility.
- **Crypto engine is `age`.** Business logic is ours; `nvlt age` is a thin passthrough, never a reimplementation.
- **Slow derivation with Argon2id.** 256 MiB, 4 iterations, 4 threads: resistant to specialized hardware attacks and the only brake when a key file sits on disk.
- **Memory zeroization.** Password, key secrets, and wrap passphrases use `SecretString` and are cleared on drop.
- **Explicit confirmation on destructive operations.** Every `remove` or destructive update asks for confirmation with a clear explanation.
- **Flexible data model.** Each password entry can have multiple users, extra fields, and embedded TOTP.
- **Unix philosophy.** The CLI prints to stdout; the user decides whether to redirect to a file.

---

## Architecture

### Cargo workspace

```
noema-vault/
├── Cargo.toml              # workspace root
├── core/                   # age + KDF chain + identity + TOTP + lock→salt
├── passwords/              # subsystem 1
├── envs/                   # subsystem 2
├── files/                  # subsystem 3
├── totp/                   # subsystem 4
├── ssh/                    # subsystem 5 (ssh.age)
├── cli/                    # `nvlt` binary
├── README.md               # project overview
└── INIT.md                 # this document
```

### `core` layout

```
core/
├── crypto.rs      # age wrapper
├── kdf.rs         # Argon2id KDF chain (password over key)
├── lock.rs        # lock → salt (HKDF)
├── identity.rs    # load age X25519 identity files; optional passphrase wrap
├── totp.rs        # generation and verification (site seeds)
├── secrets.rs     # SecretString, zeroization
├── vault.rs       # public core API
└── error.rs       # typed errors
```

### Public `core` API

```rust
pub fn salt_from_lock(lock: &str) -> Result<[u8; 16], Error>;

pub fn load_identity(
    path: &Path,
    wrap_passphrase: Option<&SecretString>,
) -> Result<SecretString, Error>;

pub fn derive_key(
    password: &SecretString,
    key_secret: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretString, Error>;

pub fn encrypt(
    key: &SecretString,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error>;

pub fn decrypt(
    key: &SecretString,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error>;

pub fn verify_totp(
    seed: &SecretString,
    code: &str,
) -> Result<bool, Error>;

pub fn generate_totp(
    seed: &SecretString,
) -> Result<String, Error>;
```

### Layer diagram

```
┌───────────────────────────────────────────────────────────┐
│                       CLI (clap)                          │
│  system init|status|backup|recover|rotate|snapshot|panic   │
│  pass │ env │ files │ totp │ ssh │ age │ unlock │ lock     │
└──────┬──────────┬──────────┬────────┬───────┬─────────────┘
       │          │          │        │       │
┌──────▼───┐ ┌────▼────┐ ┌───▼────┐ ┌─▼─────┐ ┌▼──────┐
│passwords │ │  envs   │ │ files  │ │ totp  │ │  age  │
│ (JSON)   │ │ (JSON)  │ │(bytes) │ │(JSON) │ │(pass) │
└──────┬───┘ └────┬────┘ └───┬────┘ └─┬─────┘ └┬──────┘
       │          │          │        │        │
       └──────────┼──────────┼────────┘        │
                  │          │                 │
          ┌───────▼──────────▼───────┐  ┌──────▼──────┐
          │          core            │  │  age crate  │
          │  Argon2id chain + age    │  │ (passthrough)│
          └───────────┬──────────────┘  └─────────────┘
                      │
          ┌───────────▼──────────────┐
          │     .age files on disk   │
          └──────────────────────────┘
```

---

## Security model

### KDF chain (password layer over key layer)

```
salt      = HKDF-SHA256(lock, info="nvlt-lock-v1")   # 16 bytes, memory only

key_layer = Argon2id(                                 # from the key file
    key_secret,
    salt,
    params = { m: 256 MiB, t: 4, p: 4 }
) → 32 bytes

data_key  = Argon2id(                                 # password layer over key layer
    password,
    key_layer,
    params = { m: 256 MiB, t: 4, p: 4 }
) → 32 bytes
```

- The **main unlock key** feeds the key layer for day-to-day data: `pass.age`, `envs/*.age`, `files/*`, `totp.age`, `ssh.age`.
- The **backup unlock key** feeds the key layer for `backup.age` only.
- The chain is **sequential**: the password layer is applied over the key layer, so password-only guessing (without the key) reveals nothing, and key-only (without the password) must pass Argon2id per guess.
- The 32-byte derived key is passed to `age` as `SecretString`.
- `age` uses scrypt internally as a second derivation layer.
- The exact byte composition lives in `core/kdf.rs`; the invariants above are the contract.

### Why Argon2id, not SHA256

SHA256 is fast by design. An attacker with your `.age` files can try millions of passwords per second on a GPU. Argon2id is a KDF meant to be **slow and memory-hard**, making brute force impractical at recommended settings.

Default parameters (256 MiB memory, 4 iterations, 4 threads) balance security and unlock time. When the key file is stored on the same machine as the ciphertext, **Argon2id is the only brake on offline guessing**, which is why the costs are bumped from v1.

### The key is part of the key derivation

Unlike a config flag or a device fingerprint, the unlock key **is cryptographic material**:

- The key secret enters the KDF chain.
- Without the key, the key cannot be derived, even with the correct password.
- Without the password, holding the key still requires brute-forcing Argon2id.

**Benefit:** a stolen password alone cannot decrypt anything without the key file.

**Consequence:** losing the main key means losing daily access; the offline **backup key** + `recover` exist for that reason.

### Key custody rules (non-negotiable)

- The key path is **typed visibly** at every unlock; the password is not.
- The key is **never auto-discovered** from config or previous use.
- The main key should live **off the machine** (USB/offline). If its path is under the vault root or on the same filesystem, the CLI prints a **hard warning** at unlock.
- The backup key must be stored **strictly offline**.
- A key file may optionally be wrapped at rest with a **separate passphrase** (never the master password — that would be circular); it is decrypted in memory on use.

### Residual risks (what actually matters in v2)

1. **Session left unlocked too long** — an attacker at an unlocked terminal never hits any check. Mitigation: sensible agent TTL + sliding idle timeout; documented.
2. **Private key saved on disk unencrypted** — key + ciphertext in hand = vault open (modulo password). Mitigation: hard warning at unlock + optional passphrase wrap.

Device binding and rate limiting were removed in v2: they protect against neither risk, and a protocol-aware attacker bypasses both.

### Why derive from key material, not time-based codes

Time-based codes rotate every 30 seconds. If the vault key depended on a rotating code, re-encrypting a file could fail when the window expires. The **static key file** keeps the key stable for the session, while site TOTP codes remain a display-time convenience.

### Security chain

```
Something you know:     Master password
Something you have:     Main unlock key file (off the machine, e.g. USB)
Something you have:     Backup unlock key file (strictly offline)
Inside the vault:       Website TOTPs (site seeds)
```

- Stolen USB with the main key → still need the password.
- Stolen password → still need the key file.
- Both stolen → vault is compromised.

### Secret lifecycle

| Secret | Where it lives | When it is cleared |
|---|---|---|
| Master password | Memory (`SecretString`) | End of command (or agent TTL) |
| Main/backup unlock key | Key file (`AGE-SECRET-KEY-1…`), off the machine | Persistent; read per unlock |
| Key wrap passphrase | Memory | End of command |
| `lock` | `{vault}/config.toml` | Persistent (not secret; derives salt) |
| Derived key | Memory / agent | Agent idle TTL |
| Sync host passphrase | User’s head | Never in git |
| Sync private key | `{sync}/.nvlt-sync/host.key` (gitignore) | Persistent locally |
| Vault `.age` files | Disk / git via `host.age` | Encrypted |

### Plaintext warnings

The vault **does not write plaintext secrets by itself**, but plaintext can still reach disk:

- **stdout and redirects:** `nvlt env export profile > .env.local` writes plaintext. User responsibility.
- **Swap:** process memory may hit unencrypted swap. Prefer encrypted swap or none.
- **Core dumps:** crashes may dump memory. The CLI attempts to disable core dumps.
- **Editor temp files:** future `$EDITOR` integration may write temps.
- **Plain `String` buffers:** use `SecretString` for secrets.

### On-disk layout (local vault)

```
~/.nvlt/
├── config.toml        ← lock, KDF, paths, sync names (host.age, host.pub)
├── pass.age
├── totp.age
├── ssh.age
├── backup.age         ← data copy; NO unlock key material
├── envs/*.age
└── files/*

~/.config/nvlt/config.toml   ← points path = ~/.nvlt only

# Key files live OUTSIDE the vault root (USB/offline), e.g.:
#   /media/usb/nvlt-main.key     AGE-SECRET-KEY-1…
#   (offline copy)               AGE-SECRET-KEY-1…   ← backup key
```

No `nvlt.enc`, no `rate/` directory: both were removed in v2.

### Public git repo (sync)

```
my-repo/
├── host.pub           ← age pubkey (plaintext)
└── host.age           ← tar(config + .age): outer = sync passphrase,
                         inner = pubkey (see `nvlt system snapshot export`)
# Do NOT commit: host.key, .nvlt-sync/, any unlock key file
```

---

## Data model

### `pass.age` — Passwords with multiple users and flexible fields

Unique key is `(domain, username)`. Each entry may include:

- Password.
- Embedded TOTP (optional): seed, algorithm, digits, period.
- Extra fields (optional): `{key, value}` for PIN, recovery codes, security questions, etc.

```json
{
  "version": 2,
  "entries": [
    {
      "domain": "github.com",
      "username": "work@company.com",
      "password": "...",
      "totp": {
        "seed": "JBSWY3DPEHPK3PXP",
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30
      },
      "notes": "work account",
      "fields": [
        { "key": "PIN", "value": "1234" },
        { "key": "recovery_code", "value": "abc-123" }
      ],
      "created_at": "2026-10-07T10:00:00Z",
      "updated_at": "2026-10-07T10:00:00Z"
    }
  ]
}
```

### `envs/<profile>.age` — Environment variables

```json
{
  "version": 1,
  "profile": "project-x",
  "vars": [
    { "key": "DATABASE_URL", "value": "postgres://..." },
    { "key": "API_KEY", "value": "..." }
  ]
}
```

### `files/*` — Arbitrary files

Raw bytes encrypted with `age`. No JSON wrapper.

### `totp.age` — Standalone TOTP

For 2FA-only services. Site TOTPs tied to logins live embedded in `pass.age`. This subsystem is unchanged from v1: it stores **site seeds**, not the vault lock.

```json
{
  "version": 1,
  "entries": [
    {
      "site": "2fa-only.example",
      "account": "you",
      "seed": "JBSWY3DPEHPK3PXP",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "created_at": "2026-10-07T10:00:00Z"
    }
  ]
}
```

### `backup.age` — Data backup

**Does NOT contain unlock key material.** Only a copy of vault data, encrypted with the backup-key-derived key.

```json
{
  "version": 2,
  "data": {
    "passwords": { ... },
    "envs": { ... },
    "files": [ ... ],
    "totp": { ... }
  },
  "created_at": "2026-10-07T10:00:00Z"
}
```

---

## CLI

Lifecycle and admin commands live under `system`; data commands stay top level. There is **no `help` subcommand** — use `--help` anywhere, or run bare `nvlt` for the command list.

### Password commands

```bash
nvlt pass search <domain>
nvlt pass search <domain> --user <username>
nvlt pass get <domain> <username>
nvlt pass list
nvlt pass add <domain>
nvlt pass edit <domain> <username>
nvlt pass remove <domain> <username>
```

**Example:**

```bash
$ nvlt pass get github.com work@company.com
Password: ********
TOTP: 123456

github.com (work@company.com)
Password:    hunter2
TOTP:        492 183 (expires in 23s)
Fields:
  PIN:       1234
  recovery:  abc-123
```

### Env commands

```bash
nvlt env list
nvlt env list <profile>
nvlt env get <profile> <key>
nvlt env set <profile> <key> <value>
nvlt env unset <profile> <key>
nvlt env add <profile>
nvlt env remove <profile>
nvlt env export <profile>
nvlt env load <profile>
```

**Example:**

```bash
$ nvlt env export project-x
export DATABASE_URL="postgres://localhost:5432/db"
export API_KEY="sk-abc123"
export LOG_LEVEL="info"

$ nvlt env export project-x > .env.local   # plaintext on disk — your choice
```

### Files commands

```bash
nvlt files encrypt <path>
nvlt files decrypt <name> <path>
nvlt files decrypt <name> --stdout
nvlt files list
nvlt files remove <name>
```

### Standalone TOTP commands

```bash
nvlt totp add <site>
nvlt totp list
nvlt totp get <site>
nvlt totp remove <site>
nvlt totp export <site> <path>
nvlt totp import <path>
```

### Age commands (thin passthrough)

```bash
nvlt age encrypt -r <age1…> [-R <recipients-file>] [-f <input>] [-o <out>]
nvlt age encrypt -p [-f <input>] [-o <out>]      # passphrase (interactive)
nvlt age decrypt -i <identity.key> [-f <input>] [-o <out>]
nvlt age identity [-o <key>] [<identity.key>]   # -o writes <key> + <key>.pub
```

### System (lifecycle, session, config, snapshot)

```bash
nvlt system init
nvlt system init --from-snapshot --path <dir> [--identity <host.key>]
nvlt system status
nvlt system backup
nvlt system recover
nvlt system rotate
nvlt system snapshot export --path <dir>
nvlt system snapshot import --path <dir>
nvlt system panic
nvlt system config show
nvlt system config set <key> <value>
nvlt system config path <path>

nvlt unlock --for 10m
nvlt lock
```

### SSH commands (`ssh.age`)

```bash
nvlt ssh register <name> --path ~/.ssh/id_ed25519 [--public …]
nvlt ssh list
nvlt ssh activate <name>
nvlt ssh deactivate <name>
nvlt ssh remove <name>
nvlt ssh open <name>
```

---

## Destructive operation confirmations

Any operation that **modifies** or **deletes** existing data prompts for explicit confirmation.

### `nvlt pass remove <domain> <username>`

```
⚠️  You are about to delete the entry:
    Domain:   github.com
    Username: work@company.com
    This action cannot be undone.

    Delete this entry? [y/N]:
```

### `nvlt pass edit <domain> <username>`

```
⚠️  You are about to modify the entry:
    Domain:   github.com
    Username: work@company.com

    The current password, TOTP seed, and fields will be overwritten.

    Continue? [y/N]:
```

### `nvlt env remove <profile>`

```
⚠️  You are about to delete the env profile: project-x
    All variables in this profile will be lost.
    This action cannot be undone.

    Delete this profile? [y/N]:
```

### `nvlt env unset <profile> <key>`

```
⚠️  You are about to remove the variable "API_KEY" from profile "project-x"
    This action cannot be undone.

    Continue? [y/N]:
```

### `nvlt files encrypt <path>`

```
⚠️  You are about to encrypt: /home/user/document.pdf
    The encrypted copy will be stored in: ~/.nvlt/files/document.pdf
    If a file with the same name already exists, it will be OVERWRITTEN.

    Continue? [y/N]:
```

### `nvlt files decrypt <name> <path>`

```
⚠️  You are about to decrypt: document.pdf
    Output will be written to: /home/user/document.pdf
    If a file already exists at that path, it will be OVERWRITTEN.

    Continue? [y/N]:
```

### `nvlt files remove <name>`

```
⚠️  You are about to delete the encrypted file: document.pdf
    This action cannot be undone.

    Delete this file? [y/N]:
```

### `nvlt totp remove <site>`

```
⚠️  You are about to delete the TOTP entry for: 2fa-only.example
    You will lose access to the 2FA codes for this service.
    This action cannot be undone.

    Delete this entry? [y/N]:
```

### `nvlt system backup`

```
⚠️  You are about to sync backup.age with the current vault state.
    The existing backup.age will be OVERWRITTEN.

    Continue? [y/N]:
```

### `nvlt system recover`

```
⚠️  You are about to recover your vault using the backup key.
    You may issue a new main unlock key.
    Your current vault files will be REPLACED.

    Continue? [y/N]:
```

### `nvlt system rotate`

```
⚠️  You are about to rotate your credentials.
    This will:
      - Optionally change your master password
      - Optionally generate a new main key
      - Optionally generate a new backup key
      - Re-encrypt all vault files

    The old credentials will no longer work.
    Make sure you have your new keys saved before continuing.

    Continue? [y/N]:
```

### `nvlt system panic`

```
⚠️  EMERGENCY WIPE. This deletes local encrypted vault files and clears `lock`.
    Type PANIC to confirm, then confirm the destructive prompt.

    PANIC
    This action cannot be undone. Continue? [y/N]:
```

---

## Workflows

### Initialize (new vault)

```bash
nvlt system init
```

1. Generate a random `lock` in `config.toml`.
2. Prompt for master password (twice).
3. Generate the **main** and **backup** age X25519 keypairs.
4. Prompt (visibly) for the **main key** path and write it; prompt (visibly) for the **backup key** path and write it, printing offline-storage instructions.
5. Derive keys with `salt = HKDF(lock)` in memory.
6. Create empty `.age` stores and `backup.age`.

No rate duplas, no recovery bundle, no device registration.

### Bootstrap from snapshot (new machine)

```bash
nvlt system init --from-snapshot --path ./my-repo [--identity ~/.backup/host.key]
```

1. Prompt for **sync host passphrase** and decrypt `host.age` with the sync private key.
2. Extract **`config.toml`** (includes **`lock`**) and all `.age` files into the vault root.
3. Prompt for **master password** and the **main unlock key** path (visibly).
4. Proof-decrypt `pass.age`. If the main key is lost, use the offline backup key with `recover` instead.

Default identity path: `{path}/.nvlt-sync/host.key` (copy from the machine that first ran `snapshot export`).

### Snapshot only (update ciphertext)

When the main key already works on this machine:

```bash
nvlt system snapshot import --path ./my-repo
nvlt unlock --for 10m
```

### Publish snapshot (git)

```bash
nvlt system snapshot export --path ./my-repo
```

The **sync host passphrase** is separate from the vault master password. The sync private key lives at `{repo}/.nvlt-sync/host.key` (add to `.gitignore`).

### Daily use — passwords

```bash
nvlt pass get github.com work@company.com
# → prompt (visible) for the main key path + (hidden) master password
# → derive data_key, decrypt pass.age in memory, display, zeroize
```

### Daily use — envs

```bash
nvlt env set project-x API_KEY sk-abc123
nvlt env export project-x > .env.local   # resulting file is plaintext
```

### Daily use — files

```bash
nvlt files encrypt /home/user/document.pdf
nvlt files decrypt document.pdf ~/Downloads/document.pdf
```

### Daily use — standalone TOTP

```bash
nvlt totp get 2fa-only.example
```

### `nvlt system backup`

1. Unlock: master password + **main key** path.
2. Prompt for the **backup key** path (visible), not a code and not pasted key bytes.
3. Derive `data_key` and `backup_key`.
4. Decrypt all data with `data_key`.
5. Re-encrypt that snapshot with `backup_key` into `backup.age`.
6. Confirm before overwrite.

**Important:** `backup.age` does **not** contain unlock key material.

### `nvlt system recover`

1. Master password + **backup key**.
2. Decrypt `backup.age` with the backup-derived key.
3. **Optionally issue a new main key.**
4. Confirm, re-encrypt stores under the restored or new key; **`ssh.age` is reset** (SSH keys are not in `backup.age`).
5. Invalidate the old main key.

**Important:** `recover` does **not** restore a lost main key itself; it replaces it.

### `nvlt system rotate`

1. Unlock with the current password and main key.
2. Optional new password and newly generated main/backup keys.
3. Confirm, snapshot vault data with the old data key, re-encrypt stores and **`ssh.age`** with the new data key (same `lock` → salt).
4. Write the new key files to the prompted paths, refresh `backup.age`, clear the agent session.
5. Run `nvlt system snapshot export` before git if you use snapshots.

### `nvlt system panic`

1. Confirm and type `PANIC`.
2. Verify the master password when `pass.age` exists.
3. Wipe local `.age` stores and clear `lock` in config; key files outside the vault root are untouched.
4. Restore with `snapshot import` or an existing clone, then `nvlt system init --from-snapshot`.
5. If the main key is lost, `recover` with the offline backup key.

---

## Shell integration

For transparent `nvlt env load`, add a wrapper to `.bashrc` / `.zshrc`:

```bash
nvlt() {
    if [[ "$1" == "env" && "$2" == "load" ]]; then
        eval "$(command nvlt env export "$3")"
    else
        command nvlt "$@"
    fi
}
```

After `nvlt unlock --for 10m`, subcommands `pass`, `env`, `files`, `totp`, and `ssh` reuse the cached key via the agent (`~/.cache/nvlt/agent/`).

---

## On-disk structure

See **On-disk layout (local vault)** above. Summary: **`lock` in config**, syncable `.age` ciphertexts, and **unlock key files kept outside the vault**.

---

## Configuration

### Bootstrap `~/.config/nvlt/config.toml`

```toml
[vault]
path = "/home/user/.nvlt"
```

### Vault `{path}/config.toml`

```toml
[vault]
path = "/home/user/.nvlt"
lock = "…opaque string from init…"
password_file = "pass.age"
envs_dir = "envs"
files_dir = "files"
totp_file = "totp.age"
backup_file = "backup.age"

[sync]
host_file = "host.age"
pub_file = "host.pub"

[kdf]
memory_cost = 262144
time_cost = 4
parallelism = 4
```

`nvlt system config show` prints bootstrap + vault config. Keys include `vault.path`, `vault.lock`, `sync.host_file`, `kdf.*`, etc. **No key path or key material is stored.**

---

## Dependencies

See workspace `Cargo.toml` for pinned versions (`hkdf`, `sha2`, `tar`, `age-core`, etc.). Subcrates depend on `core`; `cli` wires passwords, envs, files, totp, ssh, age, sync, and lifecycle.

---

## Roadmap (future ideas)

- Share envs with X25519 recipients (outside `host.age`).
- Import/export from other password managers.
- Multiple vaults per user (today: single path in bootstrap config).
- Optional GUI on the same APIs.

**Not planned:** automatic in-place migration from v1 layouts (`rate/`, `nvlt.enc` device binding). v1 vaults are re-initialized from a snapshot.

---

## Executive summary

| Topic | Decision |
|---|---|
| **Binary** | `nvlt` |
| **Language** | Rust |
| **Crypto** | Official `age` crate |
| **Vault KDF** | Argon2id chain (256 MiB, 4 iterations, 4 threads) |
| **Salt** | HKDF-SHA256 from config `lock` (`nvlt-lock-v1`), memory only |
| **Unlock** | Master password + main unlock key file (age X25519), path typed visibly |
| **Unlock keys** | Main (off machine) + backup (strictly offline); `AGE-SECRET-KEY-1…` |
| **Git snapshot** | `host.age` + `host.pub`; sync host passphrase ≠ master password |
| **Credentials** | Password + main unlock key (+ backup key for `backup.age`) |
| **Data / backup derivation** | Argon2id chain: key layer, then password layer over it |
| **Storage** | `~/.nvlt` (default) + bootstrap `~/.config/nvlt` |
| **Subsystems** | Passwords, Envs, Files, TOTP, SSH, age |
| **Backup** | Encrypted data copy; no unlock key material |
| **Recover / rotate** | Replace main key; re-encrypt stores |
| **Session** | `unlock --for` + Unix agent |
| **Confirmations** | Destructive ops require confirmation |
| **Zeroization** | `secrecy::SecretString`; core dumps disabled in CLI |
| **CLI style** | stdout; redirects are user responsibility |
| **Not in v2** | auth TOTP, rate limit, device binding, `reveal`, recovery bundle; `nvlt totp` site seeds stay |

---

## Commands by subsystem

| Subsystem | Commands |
|---|---|
| **System (lifecycle)** | `system init`, `system init --from-snapshot`, `system status`, `system backup`, `system recover`, `system rotate`, `system panic` |
| **Snapshot** | `system snapshot export --path`, `system snapshot import --path` |
| **Config** | `system config show`, `system config set`, `system config path` |
| **Session** | `unlock`, `lock` |
| **Age** | `age encrypt`, `age decrypt`, `age identity` |
| **Passwords** | `pass search`, `pass get`, `pass list`, `pass add`, `pass edit`, `pass remove` |
| **Envs** | `env list`, `env get`, `env set`, `env unset`, `env add`, `env remove`, `env export`, `env load` |
| **Files** | `files encrypt`, `files decrypt`, `files list`, `files remove` |
| **TOTP** | `totp add`, `totp list`, `totp get`, `totp remove`, `totp export`, `totp import` |
| **SSH** | `ssh register`, `ssh list`, `ssh activate`, `ssh deactivate`, `ssh remove`, `ssh open` |
