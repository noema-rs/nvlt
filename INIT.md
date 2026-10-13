# nvlt — Project documentation

## Overview

**nvlt** is a desktop secret manager written in Rust that uses **age** for encryption. It combines a master password with TOTP seeds (primary and backup) to derive **composite keys**, and exposes these subsystems:

1. **Passwords** — credential store by domain with multiple users and flexible fields.
2. **Envs** — environment variable manager with granular commands.
3. **Files** — encryption of arbitrary files.
4. **TOTP** — standalone TOTP seeds (for services without an associated login password).
5. **SSH** — keypairs registered by name; temporary activation under `~/.ssh`.

Vault data lives in `.age` files under `~/.nvlt` by default. Vault TOTP seeds live in **rate duplas** under `rate/` (fifteen `NN.rt` + `NN.enc` pairs, device-bound and signed). Failed unlock burns one RT; success does not. **Recovery bundle** + **rate-limit private key** stay off the operational machine. Legacy **`nvlt.enc`** is supported only for migration hints. **nvlt does not persist credential plaintext on its own.**

---

## Design philosophy

- **One vault, one password, primary + backup TOTP.** Day-to-day `.age` files use the key derived from password + primary seed; `backup.age` uses password + backup seed.
- **The TOTP seed is part of the KDF, not classic offline 2FA.** The 6-digit code proves live possession; seed bytes feed Argon2id.
- **Seeds in `rate/` duplas, not keyring or git.** Unlock selects the lowest valid RT slot, verifies password + TOTP, and re-wraps the paired `.enc` on success.
- **Device bind:** `device_id` in config; mismatch wipes local operational files.
- **Panic:** `nvlt panic` is the intentional compromise response: confirm, type `PANIC`, verify master password when `pass.age` exists, then wipe local `.age` stores, `rate/`, and clear `lock` / device / rate metadata in config. Git snapshot repos outside the vault root are untouched. Restore with `snapshot import` or an existing clone, then `nvlt init --from-snapshot --path <repo>` to mint new rate duplas; offline recovery bundle and rate-limit key stay off the machine.
- **Public snapshots:** `snapshot export` packs `config.toml` + `.age` (including `ssh.age` when present) into `host.age` (sync host passphrase + pubkey). Does **not** include `rate/` or recovery material. Future: `snapshot sync` for diff/merge.
- **Separation by files, not by passwords.** Each env profile, each file under `files/`, each vault entry has its own encrypted file.
- **The vault does not persist plaintext by itself.** Export to stdout or redirection to a file is the user’s responsibility.
- **Crypto engine is `age`.** Business logic is ours.
- **Slow derivation with Argon2id.** Resistant to specialized hardware attacks.
- **Memory zeroization.** Passphrase and seeds use `SecretString` and are cleared on drop.
- **Explicit confirmation on destructive operations.** Every `remove` or destructive update asks for confirmation with a clear explanation.
- **Flexible data model.** Each password entry can have multiple users, extra fields, and embedded TOTP.
- **Unix philosophy.** The CLI prints to stdout; the user decides whether to redirect to a file.

---

## Architecture

### Cargo workspace

```
noema-vault/
├── Cargo.toml              # workspace root
├── core/                   # age + KDF + TOTP + lock→salt
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
├── kdf.rs         # Argon2id + derive_wrap_key (nvlt.enc)
├── lock.rs        # lock → salt (HKDF)
├── totp.rs        # generation and verification
├── secrets.rs     # SecretString, zeroization
├── vault.rs       # public core API
└── error.rs       # typed errors
```

### Public `core` API

```rust
pub fn salt_from_lock(lock: &str) -> Result<[u8; 16], Error>;

pub fn derive_key(
    password: &SecretString,
    seed: &SecretString,
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
┌─────────────────────────────────────────────┐
│                CLI (clap)                   │
│  nvlt pass │ env │ files │ totp │ ssh │ snapshot │
└──────┬──────────┬──────────┬────────┬───────┘
       │          │          │        │
┌──────▼───┐ ┌────▼────┐ ┌───▼────┐ ┌─▼─────┐
│passwords │ │  envs   │ │ files  │ │ totp  │
│ (JSON)   │ │ (JSON)  │ │(bytes) │ │(JSON) │
└──────┬───┘ └────┬────┘ └───┬────┘ └─┬─────┘
       │          │          │        │
       └──────────┼──────────┼────────┘
                  │          │
          ┌───────▼──────────▼───────┐
          │          core            │
          │  Argon2id + age + TOTP   │
          └───────────┬──────────────┘
                      │
          ┌───────────▼──────────────┐
          │     .age files on disk   │
          └──────────────────────────┘
```

---

## Security model

### Composite key derivation

```
salt = HKDF-SHA256(lock, info="nvlt-lock-v1")  # 16 bytes, memory only

data_key = Argon2id(
    password || primary_totp_seed,
    salt,
    params = { m: 64MB, t: 3, p: 4 }
) → 32 bytes

backup_key = Argon2id(
    password || backup_totp_seed,
    salt,
    params = { m: 64MB, t: 3, p: 4 }
) → 32 bytes
```

- The **primary TOTP seed** combines with the password to derive the key for day-to-day data: `pass.age`, `envs/*.age`, `files/*`, `totp.age`, `ssh.age`.
- The **backup TOTP seed** combines with the password to derive the key that decrypts **`backup.age` only**.
- The **6-digit TOTP code** is used only to **verify** that the user holds the seed before unlock.
- The 32-byte derived key is passed to `age` as `SecretString`.
- `age` uses scrypt internally as a second derivation layer.

### Why Argon2id, not SHA256

SHA256 is fast by design. An attacker with your `.age` files can try millions of passwords per second on a GPU. Argon2id is a KDF meant to be **slow and memory-hard**, making brute force impractical at recommended settings.

Recommended parameters (64MB memory, 3 iterations, 4 threads) balance security and unlock time (~100–300ms on modern hardware).

### TOTP seed is part of the key

Unlike classic 2FA, in nvlt the TOTP seed **is not a separate authentication factor**. It is **part of the composite key**:

- The seed enters Argon2id derivation.
- Without the seed, the key cannot be derived, even with the correct password.
- The 6-digit code is only **possession verification**, not an extra cryptographic factor.

**Benefit:** stolen password alone cannot decrypt anything without the seed.

**Consequence:** losing the primary seed means losing access; backup TOTP and `recover` exist for that reason.

### Why derive from the seed, not the code

TOTP codes rotate every 30 seconds. If the key depended on the code, re-encrypting a file could fail when the window expires. Deriving from the seed keeps the key **stable for the session**.

### Security chain

```
Something you know:     Master password
Something you have:     Primary TOTP seed (external app)
Something you have:     Backup TOTP seed (offline, safe storage)
Inside the vault:       Website TOTPs (site seeds)
```

- Stolen phone with primary seed → still need the password.
- Stolen password → still need the primary seed.
- Both stolen → vault is compromised.

### Secret lifecycle

| Secret | Where it lives | When it is cleared |
|---|---|---|
| Master password | Memory (`SecretString`) | End of command (or agent TTL) |
| Primary/backup seeds | `nvlt.enc` (wrapped with master password) | Persistent locally; re-wrapped on read |
| `lock` | `{vault}/config.toml` | Persistent (not secret; derives salt) |
| TOTP code | Memory | After verification |
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
├── nvlt.enc           ← primary+backup seeds (LOCAL, not synced, mode 600)
├── pass.age
├── totp.age
├── ssh.age
├── backup.age         ← data copy; NO TOTP seeds
├── envs/*.age
└── files/*

~/.config/nvlt/config.toml   ← points path = ~/.nvlt only
```

### Public git repo (sync)

```
my-repo/
├── host.pub           ← age pubkey (plaintext)
└── host.age           ← tar(config + .age): outer = sync passphrase,
                         inner = pubkey (see `nvlt snapshot export`)
# Do NOT commit: nvlt.enc, host.key, .nvlt-sync/
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

For 2FA-only services. Site TOTPs tied to logins live embedded in `pass.age`.

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

**Does NOT contain the primary seed.** Only a copy of vault data, encrypted with the backup key.

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

### Config commands

```bash
nvlt config show
nvlt config set <key> <value>
nvlt config path <path>
```

### Lifecycle, session, and snapshot

```bash
nvlt init
nvlt init --from-snapshot --path <dir> [--identity <host.key>]
nvlt status
nvlt unlock --for 10m
nvlt lock
nvlt backup
nvlt recover
nvlt rotate
nvlt reveal primary|backup
nvlt snapshot export --path <dir>
nvlt snapshot import --path <dir>
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

### `nvlt backup`

```
⚠️  You are about to sync backup.age with the current vault state.
    The existing backup.age will be OVERWRITTEN.

    Continue? [y/N]:
```

### `nvlt recover`

```
⚠️  You are about to recover your vault using the backup TOTP.
    A new primary TOTP will be generated.
    Your current vault files will be REPLACED.

    Continue? [y/N]:
```

### `nvlt rotate`

```
⚠️  You are about to rotate your credentials.
    This will:
      - Generate a new primary TOTP
      - Generate a new backup TOTP
      - Re-encrypt all vault files
      - Optionally change your master password

    The old credentials will no longer work.
    Make sure you have your new credentials saved before continuing.

    Continue? [y/N]:
```

---

## Workflows

### Initialize (new vault)

```bash
nvlt init
```

1. Generate random `lock` in `config.toml`.
2. Prompt for master password (twice).
3. Generate and verify primary and backup TOTP seeds (QR / otpauth).
4. Derive keys with `salt = HKDF(lock)` in memory.
5. Create empty `.age` stores and `backup.age`.
6. Write **`nvlt.enc`** with both seeds (wrapped with master password).
7. Prompt to save seeds in an authenticator app (offline).

### Bootstrap from snapshot (new machine)

```bash
nvlt init --from-snapshot --path ./my-repo [--identity ~/.backup/host.key]
```

1. Prompt for **sync host passphrase** and decrypt `host.age` with the sync private key.
2. Extract **`config.toml`** (includes **`lock`**) and all `.age` files into the vault root.
3. Prompt for **master password**, primary/backup **TOTP seeds**, and verification codes.
4. Proof-decrypt `pass.age`, then write local **`nvlt.enc`**.

Default identity path: `{path}/.nvlt-sync/host.key` (copy from the machine that first ran `snapshot export`).

### Snapshot only (update ciphertext)

When **`nvlt.enc` already works** on this machine:

```bash
nvlt snapshot import --path ./my-repo
nvlt unlock --for 10m
```

### Publish snapshot (git)

```bash
nvlt snapshot export --path ./my-repo
```

The **sync host passphrase** is separate from the vault master password. The sync private key lives at `{repo}/.nvlt-sync/host.key` (add to `.gitignore`).

### Daily use — passwords

```bash
nvlt pass get github.com work@company.com
# → password + primary TOTP code
# → verify TOTP, derive data_key, decrypt pass.age in memory, display, zeroize
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

### `nvlt backup`

1. Unlock: password + **primary** TOTP code (seed from `nvlt.enc`).
2. Prompt for **backup** TOTP code (seed from `nvlt.enc`, not typed seed text).
3. Derive `data_key` and `backup_key`.
4. Decrypt all data with `data_key`.
5. Re-encrypt that snapshot with `backup_key` into `backup.age`.
6. Confirm before overwrite.

**Important:** `backup.age` does **not** contain the primary seed.

### `nvlt recover`

1. Password + backup TOTP verification.
2. Decrypt `backup.age` with `backup_key`.
3. **Generate a new primary seed.**
4. Confirm, re-encrypt stores with new `data_key`; **`ssh.age` is reset** (SSH keys are not in backup.age).
5. Update **`nvlt.enc`** with the new primary seed.
6. Display the new primary seed.

**Important:** `recover` does **not** restore the old primary seed.

### `nvlt rotate`

1. Unlock with current credentials (seeds from `nvlt.enc`).
2. Optional new password and new primary/backup seeds (generated if you confirm rotation).
3. Confirm, snapshot vault data with the old data key, re-encrypt stores and **`ssh.age`** with the new data key (same `lock` → salt).
4. Rewrite **`nvlt.enc`**, refresh `backup.age`, clear the agent session.
5. Save printed primary/backup seeds; run `nvlt snapshot export` before git if you use snapshots.

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

See **On-disk layout (local vault)** above. Summary: **`lock` in config**, local **`nvlt.enc`**, syncable `.age` ciphertexts.

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
memory_cost = 65536
time_cost = 3
parallelism = 4
```

`nvlt config show` prints bootstrap + vault config. Keys include `vault.path`, `vault.lock`, `sync.host_file`, `kdf.*`, etc.

---

## Dependencies

See workspace `Cargo.toml` for pinned versions (`hkdf`, `sha2`, `tar`, `age-core`, etc.). Subcrates depend on `core`; `cli` wires passwords, envs, files, totp, ssh, sync, and lifecycle.

---

## Roadmap (future ideas)

- Share envs with X25519 recipients (outside `host.age`).
- Import/export from other password managers.
- Multiple vaults per user (today: single path in bootstrap config).
- Optional GUI on the same APIs.

**Not planned:** automatic migration from legacy layouts (`salt.bin`, `vault` binary name, `~/.secrets`). New installs use `~/.nvlt` + `nvlt.enc`.

---

## Executive summary

| Topic | Decision |
|---|---|
| **Binary** | `nvlt` |
| **Language** | Rust |
| **Crypto** | Official `age` crate |
| **Vault KDF** | Argon2id (64MB, 3 iterations, 4 threads) |
| **Salt** | HKDF-SHA256 from config `lock` (`nvlt-lock-v1`), memory only |
| **Vault seeds** | Local `nvlt.enc` (master-password wrap); not in git |
| **Git snapshot** | `host.age` + `host.pub`; sync host passphrase ≠ master password |
| **Credentials** | Password + primary TOTP seed + backup TOTP seed |
| **Data / backup derivation** | Argon2id(password ∥ seed, salt) |
| **Storage** | `~/.nvlt` (default) + bootstrap `~/.config/nvlt` |
| **Subsystems** | Passwords, Envs, Files, TOTP, SSH |
| **Backup** | Encrypted data copy; no primary seed |
| **Recover / rotate** | Update stores and `nvlt.enc` |
| **Session** | `unlock --for` + Unix agent |
| **Confirmations** | Destructive ops require confirmation |
| **Zeroization** | `secrecy::SecretString`; core dumps disabled in CLI |
| **CLI style** | stdout; redirects are user responsibility |

---

## Commands by subsystem

| Subsystem | Commands |
|---|---|
| **Lifecycle** | `init`, `init --from-snapshot`, `status`, `backup`, `recover`, `rotate`, `reveal`, `unlock`, `lock` |
| **Snapshot** | `snapshot export --path`, `snapshot import --path` |
| **Config** | `config show`, `config set`, `config path` |
| **Passwords** | `pass search`, `pass get`, `pass list`, `pass add`, `pass edit`, `pass remove` |
| **Envs** | `env list`, `env get`, `env set`, `env unset`, `env add`, `env remove`, `env export`, `env load` |
| **Files** | `files encrypt`, `files decrypt`, `files list`, `files remove` |
| **TOTP** | `totp add`, `totp list`, `totp get`, `totp remove`, `totp export`, `totp import` |
| **SSH** | `ssh register`, `ssh list`, `ssh activate`, `ssh deactivate`, `ssh remove`, `ssh open` |
