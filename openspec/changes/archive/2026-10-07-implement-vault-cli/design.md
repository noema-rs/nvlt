## Goals / Non-Goals

**Goals:** clap derive tree matching INIT; `Session` struct holding derived key for one command; English prompts; config defaults.

**Non-Goals:** OS keyring (lifecycle); shell wrapper install script optional doc only.

## Decisions

- Each command: prompt password + TOTP → verify → derive → run → zeroize session.
- `config path` updates config file atomically.
- Binary name `vault` in `cli/Cargo.toml` `[[bin]]`.

## Risks / Trade-offs

- Repeated unlock per command is intentional (no daemon).
