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
- **WHEN** `init` is invoked without `--migrate` and the vault is already initialized (for example `lock` is set and core stores exist)
- **THEN** init fails with a message that names the vault path and warns that re-init causes data loss without password, seeds, or backup, and directs the user to `init --migrate` or recover

#### Scenario: Init blocked when vault exists
- **WHEN** `init` is invoked without `--migrate` and encrypted stores already exist under the configured vault root
- **THEN** init fails and does not overwrite existing ciphertext

### Requirement: Backup sync
The system SHALL decrypt all data-key-protected content and re-encrypt a copy into `backup.age` using the backup-derived key, without including TOTP seeds in the backup payload. Backup SHALL load the backup seed from `nvlt.enc` after master password unlock and backup TOTP code verification, not by prompting for seed text.

#### Scenario: Backup overwrite
- **WHEN** backup runs
- **THEN** the user confirms overwrite of existing `backup.age` before write

#### Scenario: Backup code only
- **WHEN** backup requires the backup factor
- **THEN** the user supplies the 6-digit backup authenticator code, not the backup seed string

### Requirement: Recover from backup
The system SHALL restore data from `backup.age` using password and backup TOTP verification, generate a new primary TOTP seed, re-encrypt all data files with the new data key, update `nvlt.enc`, and warn that the old primary seed is discarded.

#### Scenario: Recover confirmation
- **WHEN** recover is invoked
- **THEN** the user confirms replacement of current vault files before proceeding

### Requirement: Rotate credentials
The system SHALL optionally change master password and SHALL generate new primary and backup TOTP seeds, re-encrypt all vault files and backup, update `nvlt.enc`, and invalidate old credentials after confirmed rotation.

#### Scenario: Rotate
- **WHEN** rotation completes
- **THEN** unlock with old password or old seeds fails and new seeds are shown once for the user to save in their authenticator apps

### Requirement: Unlock flow for daily use
Each command that accesses encrypted data SHALL prompt for master password and primary TOTP code unless a valid agent session exists, load the primary seed from `nvlt.enc`, verify the code, derive the data key using salt from `lock`, re-wrap `nvlt.enc` after seed use, and clear secrets when finished.

#### Scenario: Failed unlock
- **WHEN** password or TOTP verification fails
- **THEN** no plaintext vault content is exposed and no encrypted files are modified

#### Scenario: No seed text prompt on unlock
- **WHEN** unlock runs and `nvlt.enc` is present
- **THEN** the CLI does not ask for the primary seed string

## ADDED Requirements

### Requirement: Init migrate
The CLI SHALL support `init --migrate` for vault directories that already contain encrypted stores and `config.toml` (typically after `sync pull`) but may lack `nvlt.enc`. Migrate SHALL read `lock` from config, derive KDF salt only in memory, prompt for master password, primary and backup TOTP seeds, and 6-digit codes for both seeds, then SHALL verify that derived keys decrypt existing ciphertext before writing `nvlt.enc`.

#### Scenario: Successful migrate
- **WHEN** the user supplies correct password, seeds, and codes for existing `.age` files and config contains a valid `lock`
- **THEN** migrate writes `nvlt.enc` and reports success without re-encrypting all stores unnecessarily

#### Scenario: Failed proof decrypt
- **WHEN** credentials do not decrypt existing data
- **THEN** migrate fails, does not write `nvlt.enc`, and leaves existing ciphertext unchanged

#### Scenario: Migrate not for empty vault
- **WHEN** `init --migrate` runs on a directory with no encrypted vault stores
- **THEN** the command fails and directs the user to plain `init`

#### Scenario: Missing config lock
- **WHEN** `init --migrate` runs and `config.toml` has no `lock` field
- **THEN** migrate fails with a clear error directing the user to fix config or run `sync pull`

### Requirement: Reveal TOTP seed
The CLI SHALL expose `nvlt reveal primary` and `nvlt reveal backup` which accept master password and the corresponding 6-digit TOTP code, then print the seed or otpauth URI once to stdout after successful verification.

#### Scenario: Reveal primary
- **WHEN** `nvlt reveal primary` succeeds
- **THEN** the seed or uri is printed to stdout and not written to disk by default

#### Scenario: Reveal denied on bad code
- **WHEN** the TOTP code does not match
- **THEN** no seed material is printed
