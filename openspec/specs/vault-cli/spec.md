## Purpose

Defines the user-facing CLI structure, confirmation UX, configuration commands, key custody prompts, session agent, and shell integration for `vault env load`.
## Requirements
### Requirement: Subcommand structure
The binary **`nvlt`** SHALL expose lifecycle and admin commands under `system`: `init`, `status`, `backup`, `recover`, `rotate`, `snapshot` (with `export` and `import`), `panic`, and `config`. Data commands SHALL stay top level: `pass`, `env`, `files`, `totp`, `ssh`, `unlock`, `lock`, and `age` (the `agent` command stays hidden). `nvlt system init --from-snapshot` SHALL accept an optional bundle directory argument and optional `--identity`, prompting interactively when omitted. Snapshot export/import SHALL accept an optional bundle directory argument and prompt for the sync identity key path. Sensitive file paths (snapshot bundle, sync identity, age input/output, unlock keys) SHALL be prompted interactively with visible echo when not passed as arguments, so secrets are less likely to appear in shell history. The CLI SHALL NOT expose `--migrate`. The CLI SHALL NOT provide a `help` subcommand: `--help` works on every command and a bare `nvlt` invocation prints the command list. The CLI SHALL NOT provide `reveal` or `rate-limit` commands. Documentation in INIT.md SHALL use the `nvlt` name and snapshot commands.

#### Scenario: Init help
- **WHEN** the user runs `nvlt system init --help`
- **THEN** `--from-snapshot` and `--identity` are listed

#### Scenario: Command list
- **WHEN** the user runs the binary with `--help` or with no arguments
- **THEN** the `system` group and the data commands `pass`, `env`, `files`, `totp`, `ssh`, `unlock`, `lock`, and `age` are listed, and no `reveal` or `rate-limit` entries appear

#### Scenario: No help subcommand
- **WHEN** the user runs `nvlt help`
- **THEN** the command is not treated as a help topic and the user is directed to `--help`

#### Scenario: Panic help
- **WHEN** the user runs `nvlt system panic --help`
- **THEN** the command describes emergency local wipe and recovery expectations

### Requirement: Key path prompt and custody warning
Every operation that needs the unlock key SHALL prompt for the key file path with the path echoed visibly, while the master password prompt stays hidden. The CLI SHALL NEVER auto-discover, infer, or silently reuse a key path. When the resolved key path is under the vault root or on the same filesystem as the vault, the CLI SHALL print a hard warning that the key should be kept off the machine before proceeding.

#### Scenario: Visible path, hidden password
- **WHEN** unlock prompts for credentials
- **THEN** the typed key path is echoed on screen and the typed password is not

#### Scenario: Key on the vault filesystem
- **WHEN** the supplied key path resolves to a location under the vault root or on the same filesystem as the vault
- **THEN** a hard custody warning is printed before the operation proceeds

#### Scenario: Key off the machine
- **WHEN** the supplied key path resolves to removable or separate media
- **THEN** no custody warning is shown

### Requirement: Session agent
On Unix, the CLI SHALL support `nvlt unlock --for <duration>` to cache the derived data key in a local agent process with a sliding idle timeout, and `nvlt lock` to clear it. Routine subcommands SHALL reuse the agent session when the vault path matches. Unlock SHALL complete the password and key path prompts before caching a session; prompts happen only on first unlock while the session is valid.

#### Scenario: Unlock for ten minutes
- **WHEN** the user runs `nvlt unlock --for 10m` and completes password and key prompts
- **THEN** subsequent data commands skip unlock prompts until idle timeout or `nvlt lock`

#### Scenario: Agent status
- **WHEN** the user runs `nvlt system status`
- **THEN** agent lock state and remaining idle time are shown when available

#### Scenario: Prompts only on first unlock
- **WHEN** a valid agent session exists and the user runs a data command
- **THEN** no password or key path prompt is shown

### Requirement: Unified destructive confirmations
Modify, delete, overwrite, backup sync, recover, rotate, snapshot import when local vault files would be replaced, and ssh remove operations SHALL use a consistent confirmation prompt explaining affected resources and defaulting to no.

#### Scenario: Default deny
- **WHEN** the user presses Enter without yes at a confirmation prompt
- **THEN** the operation is aborted with no data change

### Requirement: Config commands
The system SHALL support `nvlt system config show`, `config set <key> <value>`, and `config path <path>`. Full settings live in `{vault.path}/config.toml`; `~/.config/nvlt/config.toml` SHALL bootstrap the vault directory path.

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
The CLI SHALL implement `nvlt system snapshot export [directory]` and `nvlt system snapshot import [directory]` as specified in vault-sync. Export SHALL run implicit backup, prompt for bundle and identity paths when omitted, prompt for the sync host passphrase when building the archive, and prompt for the backup key when backup runs. Import SHALL prompt for the sync host passphrase and SHALL confirm before overwriting existing vault files.

#### Scenario: Snapshot help
- **WHEN** the user runs `nvlt system snapshot --help`
- **THEN** `export` and `import` subcommands and optional directory arguments are listed

#### Scenario: Import overwrite confirmation
- **WHEN** import would overwrite files under the vault root
- **THEN** the user sees a confirmation prompt and the command aborts if they do not accept

### Requirement: SSH CLI
The CLI SHALL implement `nvlt ssh` with at least `add`, `ls`, `activate`, `deactivate`, and `del` subcommands keyed by entry name.

#### Scenario: SSH help
- **WHEN** the user runs `nvlt ssh --help`
- **THEN** add and activate subcommands are listed

### Requirement: Age CLI
The CLI SHALL implement `nvlt age encrypt`, `nvlt age decrypt`, and `nvlt age identity` as a thin passthrough over the age library, as specified in vault-age.

#### Scenario: Age help
- **WHEN** the user runs `nvlt age --help`
- **THEN** `encrypt`, `decrypt`, and `identity` subcommands are listed
