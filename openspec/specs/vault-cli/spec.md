## Purpose

Defines the user-facing CLI structure, confirmation UX, configuration commands, session agent, and shell integration for `vault env load`.
## Requirements
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

### Requirement: Session agent
On Unix, the CLI SHALL support `nvlt unlock --for <duration>` to cache the derived data key in a local agent process with a sliding idle timeout, and `nvlt lock` to clear it. Routine subcommands SHALL reuse the agent session when the vault path matches. Unlock SHALL complete rate dupla and device checks before caching a session.

#### Scenario: Unlock for ten minutes
- **WHEN** the user runs `nvlt unlock --for 10m` and completes password and authenticator verification
- **THEN** subsequent data commands skip unlock prompts until idle timeout or `nvlt lock`

#### Scenario: Agent status
- **WHEN** the user runs `nvlt status`
- **THEN** agent lock state, remaining idle time, rate generation, and count of valid rate slots are shown when available

### Requirement: Rate-limit renew command
The CLI SHALL implement `nvlt rate-limit renew` with required `--bundle` and `--rate-limit-key` paths, prompting for master password and primary TOTP before minting a new generation of duplas.

#### Scenario: Renew help
- **WHEN** the user runs `nvlt rate-limit renew --help`
- **THEN** required bundle and rate-limit key flags are documented

### Requirement: Unified destructive confirmations
Modify, delete, overwrite, backup sync, recover, rotate, snapshot import when local vault files would be replaced, and ssh remove operations SHALL use a consistent confirmation prompt explaining affected resources and defaulting to no.

#### Scenario: Default deny
- **WHEN** the user presses Enter without yes at a confirmation prompt
- **THEN** the operation is aborted with no data change

### Requirement: Config commands
The system SHALL support `config show`, `config set <key> <value>`, and `config path <path>`. Full settings live in `{vault.path}/config.toml`; `~/.config/nvlt/config.toml` SHALL bootstrap the vault directory path.

#### Scenario: Path override
- **WHEN** config path is set
- **THEN** subsequent commands use the new vault directory

### Requirement: Shell wrapper for env load
Documentation SHALL provide a shell function that intercepts `nvlt env load <profile>` and evaluates export output from `nvlt env export`.

#### Scenario: Load profile
- **WHEN** the wrapper is installed and load is invoked
- **THEN** variables from the profile are set in the current shell

### Requirement: CLI error presentation
The CLI binary SHALL present errors to users with readable diagnostics (miette-style reports and styling via owo-colors) while library crates continue to use structured thiserror types.

#### Scenario: User-facing failure
- **WHEN** a command fails in the CLI
- **THEN** the user sees a formatted error without secret values in the output

### Requirement: Snapshot CLI
The CLI SHALL implement `nvlt snapshot export --path <directory>` and `nvlt snapshot import --path <directory>` as specified in vault-sync. Export SHALL run implicit backup, prompt for the sync host passphrase when building the host archive, and prompt for backup TOTP when backup runs. Import SHALL prompt for the sync host passphrase and SHALL confirm before overwriting existing vault files.

#### Scenario: Snapshot help
- **WHEN** the user runs `nvlt snapshot --help`
- **THEN** `export` and `import` subcommands and required `--path` are listed

#### Scenario: Import overwrite confirmation
- **WHEN** import would overwrite files under the vault root
- **THEN** the user sees a confirmation prompt and the command aborts if they do not accept

### Requirement: Reveal CLI
The CLI SHALL implement `nvlt reveal primary` and `nvlt reveal backup` as specified in vault-lifecycle.

#### Scenario: Reveal help
- **WHEN** the user runs `nvlt reveal --help`
- **THEN** `primary` and `backup` subcommands are listed

### Requirement: SSH CLI
The CLI SHALL implement `nvlt ssh` with at least `register`, `list`, `activate`, `deactivate`, and `remove` subcommands keyed by entry name.

#### Scenario: SSH help
- **WHEN** the user runs `nvlt ssh --help`
- **THEN** register and activate subcommands are listed

