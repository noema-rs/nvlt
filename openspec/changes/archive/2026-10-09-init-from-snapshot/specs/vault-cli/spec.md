## MODIFIED Requirements

### Requirement: Subcommand structure
The binary **`nvlt`** SHALL expose subcommands `pass`, `env`, `files`, `totp`, `ssh`, `config`, and top-level `init`, `status`, `unlock`, `lock`, `backup`, `recover`, `rotate`, **`snapshot`** (with `export` and `import`), and **`reveal`**. Init SHALL accept **`--from-snapshot --path`** and optional **`--identity`** for bootstrapping from a host archive. Init SHALL NOT expose `--migrate`. Documentation in INIT.md SHALL use the `nvlt` name and snapshot commands.

#### Scenario: Help
- **WHEN** the user runs the binary with `--help`
- **THEN** all subsystems, lifecycle commands, `snapshot`, and `ssh` are listed

#### Scenario: Init help
- **WHEN** the user runs `nvlt init --help`
- **THEN** `--from-snapshot` and `--identity` are listed
