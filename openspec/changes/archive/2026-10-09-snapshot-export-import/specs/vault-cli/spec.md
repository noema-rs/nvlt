## MODIFIED Requirements

### Requirement: Subcommand structure
The binary **`nvlt`** SHALL expose subcommands `pass`, `env`, `files`, `totp`, `ssh`, `config`, and top-level `init`, `status`, `unlock`, `lock`, `backup`, `recover`, `rotate`, **`snapshot`** (with `export` and `import`), and **`reveal`**. Init SHALL accept **`--migrate`** for attaching to existing ciphertexts. Documentation in INIT.md SHALL use the `nvlt` name and snapshot commands.

#### Scenario: Help
- **WHEN** the user runs the binary with `--help`
- **THEN** all subsystems, lifecycle commands, `snapshot`, and `ssh` are listed

### Requirement: Unified destructive confirmations
Modify, delete, overwrite, backup sync, recover, rotate, snapshot import when local vault files would be replaced, and ssh remove operations SHALL use a consistent confirmation prompt explaining affected resources and defaulting to no.

#### Scenario: Default deny
- **WHEN** the user presses Enter without yes at a confirmation prompt
- **THEN** the operation is aborted with no data change

## REMOVED Requirements

### Requirement: Sync CLI
**Reason**: Replaced by Snapshot CLI requirement.
**Migration**: Use `nvlt snapshot export|import --path`.

## ADDED Requirements

### Requirement: Snapshot CLI
The CLI SHALL implement `nvlt snapshot export --path <directory>` and `nvlt snapshot import --path <directory>` as specified in vault-sync. Export SHALL run implicit backup, prompt for the sync host passphrase when building the host archive, and prompt for backup TOTP when backup runs. Import SHALL prompt for the sync host passphrase and SHALL confirm before overwriting existing vault files.

#### Scenario: Snapshot help
- **WHEN** the user runs `nvlt snapshot --help`
- **THEN** `export` and `import` subcommands and required `--path` are listed

#### Scenario: Import overwrite confirmation
- **WHEN** import would overwrite files under the vault root
- **THEN** the user sees a confirmation prompt and the command aborts if they do not accept
