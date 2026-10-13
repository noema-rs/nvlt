# Proposal: init --from-snapshot

Replace `init --migrate` with **`nvlt init --from-snapshot --path <dir>`** (optional **`--identity <host.key>`**) that:

1. Decrypts `host.age` (sync host passphrase + age identity)
2. Materializes vault `config.toml` (with `lock`) and `.age` files
3. Prompts for vault master password, primary/backup TOTP seeds and codes
4. Proof-decrypts existing ciphertext and writes local **`nvlt.enc`**

`snapshot import` remains for updating ciphertext only when `nvlt.enc` already works.

## Non-goals

- `snapshot sync` (merge/diff)
- Automatic git commit
