# Design

- Bootstrap TOML only stores `vault.path`; authoritative settings live next to ciphertext.
- `load_config` creates missing bootstrap and vault-local config with INIT defaults.
- `init` checks `salt.bin` before any writes; failure explains delete-salt data-loss risk.
- Init QR uses otpauth URIs (issuer Vault, accounts primary/backup) written via shared `write_qr_png`.
