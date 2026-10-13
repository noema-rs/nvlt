## MODIFIED Requirements

### Requirement: Subcommand structure
The binary **`nvlt`** SHALL expose subcommands `pass`, `env`, `files`, `totp`, `ssh`, `config`, and top-level `init`, `status`, `unlock`, `lock`, `backup`, `recover`, `rotate`, **`snapshot`** (with `export` and `import`), **`rate-limit`** (with `renew`), **`panic`**, and **`reveal`**. Init SHALL accept **`--from-snapshot --path`** and optional **`--identity`** for bootstrapping from a host archive. Init SHALL NOT expose `--migrate`. Documentation in INIT.md SHALL use the `nvlt` name and snapshot commands.

#### Scenario: Init help
- **WHEN** the user runs `nvlt init --help`
- **THEN** `--from-snapshot` and `--identity` are listed

#### Scenario: Help
- **WHEN** the user runs the binary with `--help`
- **THEN** all subsystems, lifecycle commands, `snapshot`, `rate-limit`, `panic`, and `ssh` are listed

#### Scenario: Panic help
- **WHEN** the user runs `nvlt panic --help`
- **THEN** the command describes emergency local wipe and recovery expectations
