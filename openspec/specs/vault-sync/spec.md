# vault-sync Specification

## Purpose
Defines how nvlt packages vault ciphertext and configuration for a public or shared snapshot directory using an age-based outer layer distinct from vault KDF keys, without exposing local unlock key material.
## Requirements
### Requirement: Snapshot export and import
The CLI SHALL expose `nvlt system snapshot export [directory]` and `nvlt system snapshot import [directory]` where the optional directory is the **snapshot bundle** root (for example a git clone containing `user.age` and `user.pub`). When the directory is omitted, the CLI SHALL prompt for it interactively. Export SHALL refresh the snapshot bundle after successfully completing a vault backup. Import SHALL decrypt the snapshot bundle and materialize vault files into the configured local vault root.

#### Scenario: Prompted bundle directory
- **WHEN** the user runs `snapshot export` or `snapshot import` without a directory argument
- **THEN** the CLI prompts for the snapshot bundle directory and makes no changes if the prompt is cancelled

#### Scenario: Backup before export
- **WHEN** `snapshot export` runs successfully
- **THEN** the system refreshes `backup.age` using the same rules as `nvlt system backup` before building the snapshot bundle

#### Scenario: Import materializes vault tree
- **WHEN** `snapshot import` succeeds
- **THEN** `config.toml` and all packed `.age` files exist under the local vault root and unlock key files are not created or overwritten

#### Scenario: Import confirms overwrite
- **WHEN** `snapshot import` would overwrite existing files under the local vault root
- **THEN** the user MUST confirm before any file is replaced; declining aborts with no changes

#### Scenario: Import on empty vault root
- **WHEN** `snapshot import` runs and the vault root has no conflicting files
- **THEN** import proceeds without an overwrite confirmation beyond custody warnings

### Requirement: Sync bundle contents
The snapshot bundle SHALL contain the vault-local `config.toml` and every data `.age` file under the configured vault root (including `pass.age`, `totp.age`, `backup.age`, and encrypted files under `envs/` and `files/`). The bundle SHALL NOT contain unlock key files, the sync private key, legacy `nvlt.enc`, or any on-disk salt file.

#### Scenario: Local secrets excluded
- **WHEN** export completes
- **THEN** unlock key files and the sync private key are absent from the snapshot bundle directory

#### Scenario: Config travels inside bundle
- **WHEN** a recipient decrypts the snapshot bundle via import
- **THEN** they obtain a `config.toml` that includes the `lock` field used for in-memory KDF salt derivation

### Requirement: Configurable sync artifact names
Vault configuration SHALL allow setting the basenames (or relative paths within the snapshot directory) for the outer ciphertext file and the public key file. Defaults SHALL be `user.age` and `user.pub`.

#### Scenario: Custom basename
- **WHEN** sync artifact names are configured to non-default values
- **THEN** export writes and import reads those filenames under the bundle directory

#### Scenario: Defaults
- **WHEN** sync names are not configured
- **THEN** export writes `user.age` and `user.pub` under the bundle directory

### Requirement: Separate bundle and identity paths
The sync age private key SHALL live at a user-chosen path **outside** the published snapshot bundle directory. Export, import, and `init --from-snapshot` SHALL prompt separately for the bundle directory and the sync identity private key path (echoed visibly). The CLI SHALL warn when the bundle directory is nested inside the vault root or shares a filesystem with the vault.

#### Scenario: Export prompts both paths
- **WHEN** the user runs snapshot export
- **THEN** the CLI prompts for the bundle directory and the sync identity key path before writing ciphertext

#### Scenario: Import prompts identity path
- **WHEN** the user runs snapshot import
- **THEN** the CLI prompts for the sync identity private key path in addition to the bundle directory

#### Scenario: First export creates identity file
- **WHEN** export runs and the identity path does not exist
- **THEN** the CLI generates a new age keypair, writes the private key to the prompted path with restrictive permissions, and writes only the public key into the bundle directory

### Requirement: Sync age keypair
The system SHALL use an age X25519 keypair dedicated to snapshot transport. The public key SHALL be stored in the snapshot bundle as plaintext in the configured public file (default `user.pub`). The private key SHALL NOT be stored inside the published bundle directory.

#### Scenario: Import requires private key
- **WHEN** a user runs import without the sync private key at the prompted path
- **THEN** decryption of the archive fails and no vault plaintext is returned

### Requirement: Sync host passphrase
The system SHALL use a **sync host passphrase** distinct from the vault master password. Export SHALL prompt for this passphrase (or accept confirmation when re-exporting with an existing snapshot setup). Import SHALL prompt for the same passphrase. This passphrase SHALL NOT be used for vault KDF or for unlocking the vault.

#### Scenario: Distinct from vault master password
- **WHEN** export or import prompts for the sync host passphrase
- **THEN** the vault master password is not a valid substitute unless the user explicitly entered it as the sync passphrase during export

### Requirement: User archive artifact
The snapshot bundle SHALL contain an outer ciphertext file (default `user.age`) that encrypts the packed vault snapshot using age **both** to the public key in the configured public file **and** with a scrypt passphrase layer using the sync host passphrase. Decryption SHALL require the matching sync private key **and** the correct sync host passphrase. The vault master password SHALL NOT decrypt `user.age`.

#### Scenario: Dual factor for archive
- **WHEN** a user attempts import with the private key but wrong sync host passphrase
- **THEN** decryption fails

#### Scenario: Export and import round-trip
- **WHEN** export then import runs with the same keys, sync host passphrase, and paths on a confirmed or empty vault root
- **THEN** recovered ciphertexts and config match the exported snapshot
