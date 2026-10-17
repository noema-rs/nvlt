# cli

`nvlt` binary: unlock with the master password **and** a private key file kept off the machine (age X25519).

Every command documents itself: `nvlt --help`, `nvlt system snapshot --help`, etc.
Lifecycle and admin commands live under `nvlt system`.

## Configuration

- **Bootstrap:** `~/.config/nvlt/config.toml` — vault root path only.
- **Vault config:** `{vault.path}/config.toml` — `lock` (KDF salt source), KDF, sync filenames, store paths.
- No unlock key path or key material is ever stored in configuration.

Default vault root: `~/.nvlt` with `pass.age`, `totp.age`, `backup.age`, `envs/`, `files/`, `ssh.age`.

## Lifecycle

```bash
nvlt system init                    # new vault; writes main + backup key files
nvlt system init --from-snapshot --path ./git   # new machine: host.age
nvlt system snapshot export --path ./git  # backup + host.age (passphrase + pubkey layers)
nvlt system snapshot import --path ./git  # confirms before overwrite
nvlt system backup                  # refresh backup.age (master password + backup key)
nvlt system recover                 # restore from backup.age, issue a new main key
nvlt system rotate                  # change password / rotate keys
nvlt system status
nvlt system panic                   # emergency local wipe
```

## Session agent (Unix)

```bash
nvlt unlock --for 10m
nvlt pass ls
nvlt lock
```

Agent cache: `~/.cache/nvlt/agent/`.

## age passthrough

```bash
nvlt age identity                            # print a new age identity
nvlt age identity -o key.txt                 # write key.txt (private) + key.txt.pub
nvlt age identity key.txt                    # print the public key of a key file
nvlt age encrypt -r age1... -f file -o out.age  # encrypt to a recipient
nvlt age encrypt -p -f file -o out.age          # encrypt with a passphrase
nvlt age decrypt -i key.txt -f out.age          # decrypt with an identity
```

## SSH keys

```bash
nvlt ssh add mykey
# optional: nvlt ssh add mykey --public
nvlt ssh activate mykey
nvlt ssh deactivate mykey
```

Full design and CLI reference: [INIT.md](../INIT.md) and [README.md](../README.md).
