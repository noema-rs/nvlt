# nvlt

Desktop secret manager in Rust. Vault data is stored as **age**-encrypted files; unlock combines a **master password** with a **private key file** (age X25519) kept off the machine. A second, strictly offline **backup key** protects `backup.age` and powers `recover`.

This is **version 2**: no auth TOTP, no rate limit, no device binding. v1 vaults are re-initialized from a snapshot. See [`VERSION_2.md`](./VERSION_2.md).

## Features

- **Passwords** — `(domain, username)` entries with optional embedded TOTP and custom fields
- **Envs** — per-profile environment variables
- **Files** — encrypt arbitrary files into the vault
- **TOTP** — standalone site seeds (separate from login passwords; unchanged from v1)
- **SSH** — named keys in `ssh.age`, activate/deactivate under `~/.ssh`
- **Age** — `age encrypt` / `decrypt` / `identity` as a thin passthrough over the `age` crate
- **Snapshot** — `system snapshot export` / `import` for `host.age` + `host.pub` in a public git repo
- **Panic** — if the machine is compromised, `nvlt system panic` wipes local ciphertext after confirmation; recovery uses your git snapshot and `nvlt system init --from-snapshot` (keep the backup key offline)

Default vault directory: `~/.nvlt`. Bootstrap config: `~/.config/nvlt/config.toml`. Unlock key files live outside the vault root (USB/offline).

## Quick start

```bash
cargo build --release -p cli    # binary: target/release/nvlt
cargo install --path cli        # optional

nvlt system init
nvlt unlock --for 10m
nvlt pass ls
```

New machine with a git clone of the snapshot repo (copy `.nvlt-sync/host.key` from the export machine or use `--identity`, and bring the main unlock key):

```bash
nvlt system init --from-snapshot --path ./my-secrets-repo
nvlt unlock --for 10m
```

To refresh ciphertext only when the main key already works:

```bash
nvlt system snapshot import --path ./my-secrets-repo
```

## Documentation

Usage guide: **[USAGE.md](./USAGE.md)** — `pass`, `totp`, `ssh`, `env`, `files`, `age`, unlock, and `system`.

Releases (tags + GitHub Actions): **[RELEASING.md](./RELEASING.md)**.

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
