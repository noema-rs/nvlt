# nvlt

Desktop secret manager in Rust. Vault data is stored as **age**-encrypted files; unlock combines a **master password** with **primary and backup TOTP seeds**. Seeds live in local **rate duplas** (`rate/NN.rt` + `rate/NN.enc`, device-bound), never in git. Keep the **recovery bundle** and **rate-limit key** off the daily-use machine.

## Features

- **Passwords** — `(domain, username)` entries with optional embedded TOTP and custom fields
- **Envs** — per-profile environment variables
- **Files** — encrypt arbitrary files into the vault
- **TOTP** — standalone site seeds (separate from login passwords)
- **SSH** — named keys in `ssh.age`, activate/deactivate under `~/.ssh`
- **Snapshot** — `snapshot export` / `import` for `host.age` + `host.pub` in a public git repo (no local `rate/` or legacy `nvlt.enc`)
- **Rate limit** — fifteen signed unlock attempts per cycle; `rate-limit renew` with offline bundle + key
- **Panic** — if the machine is compromised, `nvlt panic` wipes local ciphertext and `rate/` after confirmation; recovery uses your git snapshot and `nvlt init --from-snapshot` (keep recovery bundle + rate-limit key off the host)

Default vault directory: `~/.nvlt`. Bootstrap config: `~/.config/nvlt/config.toml`.

## Quick start

```bash
cargo build --release -p cli    # binary: target/release/nvlt
cargo install --path cli        # optional

nvlt init
nvlt unlock --for 10m
nvlt pass list
```

New machine with a git clone of the snapshot repo (copy `.nvlt-sync/host.key` from the export machine or use `--identity`):

```bash
nvlt init --from-snapshot --path ./my-secrets-repo
nvlt unlock --for 10m
```

To refresh ciphertext only when local rate duplas already work:

```bash
nvlt snapshot import --path ./my-secrets-repo
```

## Documentation

Full design, security model, data formats, and CLI reference: **[INIT.md](./INIT.md)**.

Crate-level notes: `core/`, `cli/`, `passwords/`, `envs/`, `files/`, `totp/`, `ssh/` README files.

## Development

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

Specs: `openspec/specs/` (OpenSpec).

## License

MIT — see workspace `Cargo.toml`.
