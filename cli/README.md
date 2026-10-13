# cli

`nvlt` binary: unlock with master password + primary TOTP code; seeds live in local `nvlt.enc`.

Every command documents itself: `nvlt --help`, `nvlt snapshot --help`, etc.

## Configuration

- **Bootstrap:** `~/.config/nvlt/config.toml` — vault root path only.
- **Vault config:** `{vault.path}/config.toml` — `lock` (KDF salt source), KDF, sync filenames, store paths.
- **Local only:** `{vault.path}/nvlt.enc` — wrapped primary/backup TOTP seeds (not synced).

Default vault root: `~/.nvlt` with `pass.age`, `totp.age`, `backup.age`, `envs/`, `files/`, `ssh.age`.

## Lifecycle

```bash
nvlt init                    # new vault
nvlt init --from-snapshot --path ./git   # new machine: host.age + nvlt.enc
nvlt snapshot export --path ./git  # backup + host.age (passphrase + pubkey layers)
nvlt snapshot import --path ./git  # confirms before overwrite
nvlt reveal primary|backup   # export seed with password + code
```

## Session agent (Unix)

```bash
nvlt unlock --for 10m
nvlt pass list
nvlt lock
```

Agent cache: `~/.cache/nvlt/agent/`.

## SSH keys

```bash
nvlt ssh register mykey --path ~/.ssh/id_ed25519
nvlt ssh activate mykey
nvlt ssh deactivate mykey
```

Full design and CLI reference: [INIT.md](../INIT.md) and [README.md](../README.md).
