## MODIFIED Requirements

### Requirement: Initialize new vault
The system SHALL create empty encrypted stores (`pass.age`, `envs/`, `files/`, `totp.age`), empty `backup.age`, a new random `lock` value in config, and `nvlt.enc` containing verified primary and backup TOTP seeds. Init SHALL verify both authenticators with 6-digit codes before writing encrypted data.

#### Scenario: Init
- **WHEN** init completes successfully
- **THEN** all paths exist under the configured vault directory, `lock` is set, and no plaintext TOTP seeds are written to disk except optional QR or display during setup

#### Scenario: Init QR outputs
- **WHEN** init completes successfully
- **THEN** the CLI MAY write QR PNGs under the vault root for scanning into an authenticator app

#### Scenario: Init TOTP verification
- **WHEN** init is setting up authenticators
- **THEN** the CLI generates or accepts primary material, verifies the user’s app code, then does the same for backup before creating encrypted vault files and `nvlt.enc`

#### Scenario: Init progress feedback
- **WHEN** init is running setup steps
- **THEN** the CLI prints short status lines so the user knows what is in progress

#### Scenario: Init ASCII QR
- **WHEN** init displays setup material for primary and backup seeds
- **THEN** the CLI MAY print otpauth URIs and ASCII QR codes in the terminal

#### Scenario: Init blocked when salt exists
- **WHEN** `init` is invoked without `--from-snapshot` and the vault is already initialized (for example `lock` is set and core stores exist)
- **THEN** init fails with a message that names the vault path and warns that re-init causes data loss without password, seeds, or backup, and directs the user to `init --from-snapshot` or recover

#### Scenario: Init blocked when vault exists
- **WHEN** `init` is invoked without `--from-snapshot` and encrypted stores already exist under the configured vault root
- **THEN** init fails and does not overwrite existing ciphertext

## REMOVED Requirements

### Requirement: Init migrate
**Reason**: Replaced by init from snapshot (import + local nvlt.enc in one command).
**Migration**: Use `nvlt init --from-snapshot --path <dir>` instead of `snapshot import` then `init --migrate`.

## ADDED Requirements

### Requirement: Init from snapshot
The CLI SHALL support `nvlt init --from-snapshot --path <directory>` with optional `--identity <path>` to the sync age private key (default `{path}/.nvlt-sync/host.key`). The command SHALL prompt for the sync host passphrase, decrypt and extract the snapshot into the vault root, reload configuration including `lock`, then prompt for vault master password, primary and backup TOTP seeds, and 6-digit codes, verify decrypt of existing ciphertext, and write `nvlt.enc`.

#### Scenario: New machine bootstrap
- **WHEN** the user runs `init --from-snapshot` with valid snapshot credentials and vault credentials
- **THEN** vault files and `nvlt.enc` exist locally and unlock succeeds

#### Scenario: Missing identity
- **WHEN** the sync private key is missing at the resolved identity path
- **THEN** the command fails with a clear error and does not generate a new sync keypair

#### Scenario: Failed proof decrypt
- **WHEN** vault credentials do not decrypt imported ciphertext
- **THEN** the command fails and does not write `nvlt.enc`

#### Scenario: Replace nvlt.enc
- **WHEN** `nvlt.enc` already exists
- **THEN** the user MUST confirm before replacing it after successful proof decrypt

#### Scenario: Missing config lock after extract
- **WHEN** extracted `config.toml` has no `lock` field
- **THEN** the command fails before writing `nvlt.enc`
