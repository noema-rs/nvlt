## 1. Crate setup

- [x] 1.1 Add `cli/` with pinned deps: clap, rpassword, directories, miette, owo-colors
- [x] 1.2 Config module (load/save/show/set/path)

## 2. UX primitives

- [x] 2.1 Confirm helper `[y/N]` with English templates per INIT
- [x] 2.2 Unlock: password + TOTP + derive data key

## 3. Commands

- [x] 3.1 `pass`, `env`, `files`, `totp` subcommands delegating to libs
- [x] 3.2 `config` subcommands
- [x] 3.3 `vault status` (paths exist, no decrypt)

## 4. Quality

- [x] 4.1 clippy -D warnings; smoke test `--help`
