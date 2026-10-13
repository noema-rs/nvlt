# Proposal: align config paths and init UX

Move full vault configuration to `{vault.path}/config.toml`, bootstrap with `~/.config/vault/config.toml`, block re-init when salt exists with a clear warning, and emit QR PNGs for primary/backup seeds on init.
