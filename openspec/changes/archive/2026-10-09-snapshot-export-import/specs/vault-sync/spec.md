## MODIFIED Requirements

### Requirement: Snapshot export and import
The CLI SHALL expose `nvlt snapshot export --path <directory>` and `nvlt snapshot import --path <directory>` where `<directory>` is the snapshot root (for example a git clone). Export SHALL refresh the snapshot bundle after successfully completing a vault backup. Import SHALL decrypt the snapshot bundle and materialize vault files into the configured local vault root.

#### Scenario: Path required
- **WHEN** the user runs `snapshot export` or `snapshot import` without `--path`
- **THEN** the command fails with a clear error and makes no changes

#### Scenario: Backup before export
- **WHEN** `snapshot export --path` runs successfully
- **THEN** the system refreshes `backup.age` using the same rules as `nvlt backup` before building the snapshot bundle

#### Scenario: Import materializes vault tree
- **WHEN** `snapshot import --path` succeeds
- **THEN** `config.toml` and all packed `.age` files exist under the local vault root and `nvlt.enc` is not created or overwritten

#### Scenario: Import confirms overwrite
- **WHEN** `snapshot import --path` would overwrite existing files under the local vault root
- **THEN** the user MUST confirm before any file is replaced; declining aborts with no changes

#### Scenario: Import on empty vault root
- **WHEN** `snapshot import --path` runs and the vault root has no conflicting files
- **THEN** import proceeds without an overwrite confirmation beyond any global snapshot warnings documented in vault-cli

## RENAMED Requirements

- FROM: `Pull before migrate`
- TO: `Import before migrate`

## MODIFIED Requirements

### Requirement: Import before migrate
After `snapshot import`, the user SHALL run `init --migrate` to create local `nvlt.enc` using `lock` and ciphertexts from the imported config and stores.

#### Scenario: Migrate uses imported config
- **WHEN** the user runs `init --migrate` after a successful import
- **THEN** migrate loads `lock` from `config.toml` and does not ask for a separate lock string unless config is missing or invalid

## REMOVED Requirements

### Requirement: Sync push and pull
**Reason**: Replaced by snapshot export/import naming; behavior unchanged.
**Migration**: Use `nvlt snapshot export --path` and `nvlt snapshot import --path` instead of `sync push` / `sync pull`.
