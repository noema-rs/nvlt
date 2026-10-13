# vault-sync Specification

## Purpose
Defines how nvlt packages vault ciphertext and configuration for a public or shared snapshot directory using an age-based outer layer distinct from vault KDF keys, without exposing local TOTP seed storage.
## Requirements
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
- **THEN** `config.toml` and all packed `.age` files exist under the local vault root and local rate duplas are not created or overwritten

#### Scenario: Import confirms overwrite
- **WHEN** `snapshot import --path` would overwrite existing files under the local vault root
- **THEN** the user MUST confirm before any file is replaced; declining aborts with no changes

#### Scenario: Import on empty vault root
- **WHEN** `snapshot import --path` runs and the vault root has no conflicting files
- **THEN** import proceeds without an overwrite confirmation beyond any global snapshot warnings documented in vault-cli

### Requirement: Sync bundle contents
The snapshot bundle SHALL contain the vault-local `config.toml` and every data `.age` file under the configured vault root (including `pass.age`, `totp.age`, `backup.age`, and encrypted files under `envs/` and `files/`). The bundle SHALL NOT contain the `rate/` directory, legacy `nvlt.enc`, plaintext TOTP seeds, or any on-disk salt file.

#### Scenario: Local secrets excluded
- **WHEN** export completes
- **THEN** `rate/` duplas, legacy `nvlt.enc`, and any plaintext seed files are absent from the snapshot directory output

#### Scenario: Config travels inside bundle
- **WHEN** a recipient decrypts the snapshot bundle via import
- **THEN** they obtain a `config.toml` that includes the `lock` field used for in-memory KDF salt derivation

### Requirement: Configurable sync artifact names
Vault configuration SHALL allow setting the basenames (or relative paths within the snapshot directory) for the outer ciphertext file and the public key file. Defaults SHALL be `host.age` and `host.pub`.

#### Scenario: Custom host basename
- **WHEN** sync artifact names are configured to non-default values
- **THEN** export writes and import reads those filenames under `--path`

#### Scenario: Defaults
- **WHEN** sync names are not configured
- **THEN** export writes `host.age` and `host.pub` under `--path`

### Requirement: Sync age keypair
The system SHALL use an age X25519 keypair dedicated to snapshot transport. The public key SHALL be stored in the snapshot directory as plaintext in the configured public file (default `host.pub`). The private key SHALL be stored locally outside the published snapshot tree or in a gitignored path. The public key file SHALL NOT be encrypted.

#### Scenario: First export generates keys
- **WHEN** export runs and no sync keypair exists for the chosen snapshot path
- **THEN** the CLI generates a new keypair, writes plaintext public material to the configured public file, and stores the private key locally for later import operations

#### Scenario: Subsequent export reuses keys
- **WHEN** export runs and valid sync keys already exist for the path
- **THEN** the CLI reuses them unless the user opts to rotate via a documented flag

#### Scenario: Import requires private key
- **WHEN** a user runs import without the sync private key
- **THEN** decryption of the host archive fails and no vault plaintext is returned

### Requirement: Sync host passphrase
The system SHALL use a **sync host passphrase** distinct from the vault master password. Export SHALL prompt for this passphrase (or accept confirmation when re-exporting with an existing snapshot setup). Import SHALL prompt for the same passphrase. This passphrase SHALL NOT be used for vault KDF, local rate duplas, or unlocking the vault master secret.

#### Scenario: Distinct from vault master password
- **WHEN** export or import prompts for the sync host passphrase
- **THEN** the vault master password is not a valid substitute unless the user explicitly entered it as the sync passphrase during export

#### Scenario: Export records dual encryption
- **WHEN** export creates or replaces the host archive
- **THEN** the user has supplied the sync host passphrase used for that archive

### Requirement: Host archive artifact
The snapshot directory SHALL contain an outer ciphertext file (default `host.age`) that encrypts the packed vault snapshot using age **both** to the public key in the configured public file **and** with a scrypt passphrase layer using the sync host passphrase. Decryption SHALL require the matching sync private key **and** the correct sync host passphrase. The vault master password SHALL NOT decrypt `host.age`.

#### Scenario: Dual factor for host archive
- **WHEN** a user attempts import with the private key but wrong sync host passphrase
- **THEN** decryption fails

#### Scenario: Dual factor missing key
- **WHEN** a user attempts import with the correct sync host passphrase but without the private key
- **THEN** decryption fails

#### Scenario: Public git safe ciphertext
- **WHEN** only the host archive and plaintext public key file are published
- **THEN** opening the bundle still requires the sync private key and sync host passphrase; vault TOTP seeds and local rate material remain absent from the snapshot directory

#### Scenario: Export and import round-trip
- **WHEN** export then import runs with the same keys, sync host passphrase, and path on a confirmed or empty vault root
- **THEN** recovered ciphertexts and config match the exported snapshot aside from local-only rate duplas
