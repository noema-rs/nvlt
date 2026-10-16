# nvlt usage guide

Day-to-day command reference: what each feature does and how to run it. For design, security model, and on-disk formats, see [INIT.md](./INIT.md).

**Binary:** `nvlt` (`cargo build --release -p cli` or `cargo install --path cli`).

**Terminal help:** there is no `help` subcommand; use `nvlt --help`, `nvlt pass --help`, and so on.

---

## Before using secrets

### Unlocking the vault

Most data commands (`pass`, `env`, `files`, `totp`, `ssh`, and parts of `system`) require:

1. **Master password** (hidden while typing).
2. **age private key file** (**visible** path; typically on USB or other media off the vault disk).

On **Unix**, cache the session so you do not unlock on every command:

```bash
nvlt unlock --for 10m    # idle TTL; e.g. 1h, 30m
nvlt lock                # clear cached session
```

After `unlock`, the local agent (`~/.cache/nvlt/agent/`) serves subsequent commands until the TTL expires or you run `lock`.

### Default paths

| What | Where |
|------|--------|
| Vault root | `~/.nvlt` (configurable) |
| Bootstrap config | `~/.config/nvlt/config.toml` |
| Passwords | `{vault}/pass.age` |
| Env profiles | `{vault}/envs/<profile>.age` |
| Files | `{vault}/files/*` |
| Standalone TOTP | `{vault}/totp.age` |
| SSH keys | `{vault}/ssh.age` |

### First time on a machine

```bash
nvlt system init                              # new vault
# or from a git snapshot repo:
nvlt system init --from-snapshot --path ./my-repo [--identity ./my-repo/.nvlt-sync/host.key]

nvlt unlock --for 10m
nvlt system status
```

---

## Passwords (`nvlt pass`)

Store keyed by **(domain, username)**. One domain can have many users. Each entry may include **embedded TOTP**, notes, and custom fields.

| Command | Description |
|---------|-------------|
| `nvlt pass list` | List `domain (username)` |
| `nvlt pass search <domain> [--user <username>]` | Search by domain; optional user filter |
| `nvlt pass get <domain> <username>` | Show password, current TOTP (if any), notes, fields |
| `nvlt pass add <domain>` | Interactive add (username, password, optional TOTP, notes, fields) |
| `nvlt pass edit <domain> <username>` | Interactive edit; asks for confirmation |
| `nvlt pass remove <domain> <username>` | Delete entry; asks for confirmation |

**Examples:**

```bash
nvlt pass search github.com
nvlt pass get github.com work@company.com
nvlt pass add bank.example
nvlt pass edit github.com work@company.com
```

**Typical `get` output:**

```text
github.com (work@company.com)
Password:    ********
TOTP:        492183 (expires in 23s)
Notes:       ...
Fields:
  PIN: 1234
```

**TOTP on password entries:** `add` and `edit` can store a TOTP seed on the same entry. That is separate from `nvlt totp` (standalone site seeds).

---

## TOTP / OTP (`nvlt totp`)

Second-factor codes stored **separately** from login passwords (when there is no associated credential in the vault).

| Command | Description |
|---------|-------------|
| `nvlt totp list` | Registered sites (`site (account)`) |
| `nvlt totp add <site>` | Interactive: account label + base32 seed |
| `nvlt totp get <site>` | Current 6-digit code and seconds remaining |
| `nvlt totp remove <site>` | Delete entry; asks for confirmation |
| `nvlt totp export <site> <path>` | Write QR image for migration |
| `nvlt totp import <path>` | Import from QR or seed file |

**Examples:**

```bash
nvlt totp add vendor-2fa-only
nvlt totp get vendor-2fa-only
nvlt totp export vendor-2fa-only ~/migration-qr.png
nvlt totp import ~/seed.txt
```

**When to use `pass` vs `totp`:**

- **`pass` + embedded TOTP:** login and 2FA for the same service/account.
- **`totp`:** OTP only (multiple accounts per site via the account label in `add`).

---

## SSH (`nvlt ssh`)

Private/public key material in `ssh.age`. **Activate** writes keys to `~/.ssh/nvlt_<name>` and `nvlt_<name>.pub` (file copy with restricted permissions on the private key).

| Command | Description |
|---------|-------------|
| `nvlt ssh register <name> [--public]` | Register in vault; prompts for private key path; `--public` also prompts for public key path |
| `nvlt ssh list` | Registered names |
| `nvlt ssh activate <name>` | Write keys under `~/.ssh/` |
| `nvlt ssh deactivate <name>` | Remove files created by `activate` |
| `nvlt ssh remove <name>` | Remove from vault; asks for confirmation |
| `nvlt ssh open <name>` | Activate and print `ssh` command if host/user are set, else key path |

**Examples:**

```bash
nvlt ssh register work
nvlt ssh register work --public
nvlt ssh activate work
ssh -i ~/.ssh/nvlt_work user@server
nvlt ssh deactivate work
nvlt ssh open work
```

**Note:** registration does not set host/user in the current CLI; `open` prints the key path for a manual `ssh`. After **`recover`**, **`ssh.age` is reset** (SSH keys are not in `backup.age`).

---

## Environment variables (`nvlt env`)

Encrypted profiles (one `.age` file per profile).

| Command | Description |
|---------|-------------|
| `nvlt env list` | List profiles |
| `nvlt env list <profile>` | List keys in a profile |
| `nvlt env get <profile> <key>` | One variable value |
| `nvlt env set <profile> <key> <value>` | Set variable; creates profile if needed |
| `nvlt env unset <profile> <key>` | Remove one key; asks for confirmation |
| `nvlt env add <profile>` | Empty profile |
| `nvlt env remove <profile>` | Delete profile; asks for confirmation |
| `nvlt env export <profile>` | Print `export KEY="value"` lines |
| `nvlt env load <profile>` | Same output as `export` (see shell integration below) |

**Examples:**

```bash
nvlt env set project-x DATABASE_URL postgres://localhost/db
nvlt env get project-x DATABASE_URL
nvlt env export project-x
nvlt env export project-x > .env.local   # plaintext on disk — your choice
```

### Load variables into the current shell

`env load` only prints exports. To **evaluate** them in bash/zsh, add a wrapper (from [INIT.md](./INIT.md)):

```bash
nvlt() {
    if [[ "$1" == "env" && "$2" == "load" ]]; then
        eval "$(command nvlt env export "$3")"
    else
        command nvlt "$@"
    fi
}
```

Then: `nvlt unlock --for 10m` and `nvlt env load project-x`.

---

## Files (`nvlt files`)

Encrypt arbitrary files into `{vault}/files/` (stored name = original file name).

| Command | Description |
|---------|-------------|
| `nvlt files list` | Encrypted file names |
| `nvlt files encrypt <path>` | Encrypt; confirms (warns on overwrite) |
| `nvlt files decrypt <name> <output_path>` | Decrypt to disk; confirms if overwriting |
| `nvlt files decrypt <name> --stdout` | Decrypt to stdout (pipes, viewers) |
| `nvlt files remove <name>` | Delete encrypted blob; asks for confirmation |

**Examples:**

```bash
nvlt files encrypt ~/documents/contract.pdf
nvlt files decrypt contract.pdf ~/Downloads/contract.pdf
nvlt files decrypt contract.pdf --stdout | less
```

---

## age (`nvlt age`)

Thin **age** encrypt/decrypt/identity passthrough; **does not** require vault unlock. Use for encryption outside the vault or standard age keys.

```bash
# Encrypt to recipients
nvlt age encrypt -r age1... -o out.age -f input.txt

# Encrypt with interactive passphrase
nvlt age encrypt -p -o out.age -f input.txt

# Decrypt
nvlt age decrypt -i identity.key -f out.age -o clear.txt

# Generate identity or print public key
nvlt age identity -o my-key
nvlt age identity my-key
```

Common flags: `-f` input (stdin if omitted), `-o` output (stdout if omitted), `-R` recipients file (one `age1...` per line).

---

## Session

| Command | Description |
|---------|-------------|
| `nvlt unlock --for <duration>` | Cache data key in local agent (Unix); default `10m` |
| `nvlt lock` | Clear agent session |

Data commands reuse the cached key while the agent session is active.

---

## Administration (`nvlt system`)

| Command | Purpose |
|---------|---------|
| `nvlt system init` | New vault: master password, main/backup keys, empty stores |
| `nvlt system init --from-snapshot --path <repo> [--identity <host.key>]` | Bootstrap from `host.age` in a git clone |
| `nvlt system status` | Vault path, init state, agent session (Unix) |
| `nvlt system backup` | Refresh `backup.age` using the **backup key** (offline) |
| `nvlt system recover` | Restore from `backup.age`; may issue a new main key |
| `nvlt system rotate` | Change password and/or keys; re-encrypt all stores (incl. `ssh.age`) |
| `nvlt system snapshot export --path <repo>` | Run backup, write `host.age` / `host.pub` for git |
| `nvlt system snapshot import --path <repo>` | Update local ciphertext from snapshot |
| `nvlt system panic` | Emergency local wipe (confirmation + type `PANIC`) |
| `nvlt system config show` | Bootstrap and vault `config.toml` |
| `nvlt system config set <key> <value>` | e.g. `vault.path`, `kdf.memory_cost` |
| `nvlt system config path <path>` | Set vault root in bootstrap config |

**Typical git workflow:**

```bash
# Machine A — publish
nvlt system snapshot export --path ./secrets-repo
cd secrets-repo && git add host.age host.pub && git commit && git push

# Machine B — first time
git clone ... ./secrets-repo
nvlt system init --from-snapshot --path ./secrets-repo
nvlt unlock --for 10m

# Machine B — ciphertext only
nvlt system snapshot import --path ./secrets-repo
```

The **sync host passphrase** is separate from the vault master password. Sync private key: `{repo}/.nvlt-sync/host.key` (keep out of git; use `.gitignore`).

---

## Feature summary

| Feature | Command | Vault unlock required |
|---------|---------|------------------------|
| Passwords | `nvlt pass` | Yes |
| Standalone TOTP | `nvlt totp` | Yes |
| SSH | `nvlt ssh` | Yes |
| Envs | `nvlt env` | Yes |
| Files | `nvlt files` | Yes (encrypt/decrypt) |
| age | `nvlt age` | No |
| Session | `nvlt unlock` / `lock` | N/A |
| Lifecycle | `nvlt system` | Depends on subcommand |

---

## Destructive operations

`remove`, `edit`, overwrite paths in `files`, `backup`, `recover`, `rotate`, `panic`, and similar prompts ask for explicit confirmation (`[y/N]`). Message text: [INIT.md — Destructive operation confirmations](./INIT.md#destructive-operation-confirmations).

---

## See also

- [README.md](./README.md) — overview and quick start  
- [INIT.md](./INIT.md) — full CLI reference, workflows, configuration  
- [VERSION_2.md](./VERSION_2.md) — v1 → v2 differences  
