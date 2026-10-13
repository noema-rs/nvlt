## MODIFIED Requirements

### Requirement: Subcommand structure
The binary **`nvlt`** SHALL expose subcommands `pass`, `env`, `files`, `totp`, `ssh`, `config`, and top-level `init`, `status`, `unlock`, `lock`, `backup`, `recover`, `rotate`, **`sync`** (with `push` and `pull`), and **`reveal`**. Init SHALL accept **`--migrate`** for attaching to existing ciphertexts. Documentation in INIT.md SHALL be updated to use the `nvlt` name.

#### Scenario: Help
- **WHEN** the user runs the binary with `--help`
- **THEN** all subsystems, lifecycle commands, `sync`, and `ssh` are listed

### Requirement: Session agent
On Unix, the CLI SHALL support `nvlt unlock --for <duration>` to cache the derived data key in a local agent process with a sliding idle timeout, and `nvlt lock` to clear it. Routine subcommands SHALL reuse the agent session when the vault path matches.

#### Scenario: Unlock for ten minutes
- **WHEN** the user runs `nvlt unlock --for 10m` and completes password and authenticator verification
- **THEN** subsequent data commands skip unlock prompts until idle timeout or `nvlt lock`

#### Scenario: Agent status
- **WHEN** the user runs `nvlt status`
- **THEN** agent lock state and remaining idle time are shown when available

### Requirement: Unified destructive confirmations
Modify, delete, overwrite, backup sync, recover, rotate, sync pull when local vault files would be replaced, and ssh remove operations SHALL use a consistent confirmation prompt explaining affected resources and defaulting to no.

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

## ADDED Requirements

### Requirement: Sync CLI
The CLI SHALL implement `nvlt sync push --path <directory>` and `nvlt sync pull --path <directory>` as specified in vault-sync. Push SHALL run implicit backup, prompt for the sync host passphrase when building the host archive, and prompt for backup TOTP when backup runs. Pull SHALL prompt for the sync host passphrase and SHALL confirm before overwriting existing vault files.

#### Scenario: Sync help
- **WHEN** the user runs `nvlt sync --help`
- **THEN** `push` and `pull` subcommands and required `--path` are listed

#### Scenario: Pull overwrite confirmation
- **WHEN** pull would overwrite files under the vault root
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
