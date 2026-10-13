## Why

Subsystems need a single binary, unlock flow, config, and user confirmations. Specs: `vault-cli`, `vault-config`.

## What Changes

- Add `cli/` binary `vault` with clap subcommands per INIT.
- Config load/save `~/.config/vault/config.toml`.
- Unified confirmation helper; miette + owo-colors for errors.
- Wire passwords, envs, files, totp subcommands (unlock session per command).

## Capabilities

_(Main specs only.)_

## Impact

- Depends on all subsystem crates; adds `rpassword`, `directories`, `miette`, `owo-colors` to workspace.

## Non-Goals

- `vault init`, backup, recover, rotate (lifecycle change).
