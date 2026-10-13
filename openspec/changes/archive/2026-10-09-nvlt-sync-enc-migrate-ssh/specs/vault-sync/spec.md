## Purpose

Defines how nvlt packages vault ciphertext and configuration for a public or shared sync directory using an age-based outer layer distinct from vault KDF keys, without exposing local TOTP seed storage.

## ADDED Requirements

### Requirement: Sync push and pull
The CLI SHALL expose `nvlt sync push --path <directory>` and `nvlt sync pull --path <directory>` where `<directory>` is the sync root (for example a git clone). Push SHALL refresh the sync bundle after successfully completing a vault backup. Pull SHALL decrypt the sync bundle and materialize vault files into the configured local vault root.

#### Scenario: Path required
- **WHEN** the user runs `sync push` or `sync pull` without `--path`
- **THEN** the command fails with a clear error and makes no changes

#### Scenario: Backup before push
- **WHEN** `sync push --path` runs successfully
- **THEN** the system refreshes `backup.age` using the same rules as `nvlt backup` before building the sync bundle

#### Scenario: Pull materializes vault tree
- **WHEN** `sync pull --path` succeeds
- **THEN** `config.toml` and all packed `.age` files exist under the local vault root and `nvlt.enc` is not created or overwritten

#### Scenario: Pull confirms overwrite
- **WHEN** `sync pull --path` would overwrite existing files under the local vault root
- **THEN** the user MUST confirm before any file is replaced; declining aborts with no changes

#### Scenario: Pull on empty vault root
- **WHEN** `sync pull --path` runs and the vault root has no conflicting files
- **THEN** pull proceeds without an overwrite confirmation beyond any global sync warnings documented in vault-cli

### Requirement: Sync bundle contents
The sync bundle SHALL contain the vault-local `config.toml` and every data `.age` file under the configured vault root (including `pass.age`, `totp.age`, `backup.age`, and encrypted files under `envs/` and `files/`). The bundle SHALL NOT contain `nvlt.enc`, plaintext TOTP seeds, or any on-disk salt file.

#### Scenario: Local secrets excluded
- **WHEN** push completes
- **THEN** `nvlt.enc` and any legacy plaintext seed files are absent from the sync directory output

#### Scenario: Config travels inside bundle
- **WHEN** a recipient decrypts the sync bundle via pull
- **THEN** they obtain a `config.toml` that includes the `lock` field used for in-memory KDF salt derivation

### Requirement: Configurable sync artifact names
Vault configuration SHALL allow setting the basenames (or relative paths within the sync directory) for the outer ciphertext file and the public key file. Defaults SHALL be `host.age` and `host.pub`.

#### Scenario: Custom host basename
- **WHEN** sync artifact names are configured to non-default values
- **THEN** push writes and pull reads those filenames under `--path`

#### Scenario: Defaults
- **WHEN** sync names are not configured
- **THEN** push writes `host.age` and `host.pub` under `--path`

### Requirement: Sync age keypair
The system SHALL use an age X25519 keypair dedicated to sync transport. The public key SHALL be stored in the sync directory as plaintext in the configured public file (default `host.pub`). The private key SHALL be stored locally outside the published sync tree or in a gitignored path. The public key file SHALL NOT be encrypted.

#### Scenario: First push generates keys
- **WHEN** push runs and no sync keypair exists for the chosen sync path
- **THEN** the CLI generates a new keypair, writes plaintext public material to the configured public file, and stores the private key locally for later pull operations

#### Scenario: Subsequent push reuses keys
- **WHEN** push runs and valid sync keys already exist for the path
- **THEN** the CLI reuses them unless the user opts to rotate via a documented flag

#### Scenario: Pull requires private key
- **WHEN** a user runs pull without the sync private key
- **THEN** decryption of the host archive fails and no vault plaintext is returned

### Requirement: Sync host passphrase
The system SHALL use a **sync host passphrase** distinct from the vault master password. Push SHALL prompt for this passphrase (or accept confirmation when re-pushing with an existing sync setup). Pull SHALL prompt for the same passphrase. This passphrase SHALL NOT be used for vault KDF, `nvlt.enc`, or unlocking the vault master secret.

#### Scenario: Distinct from vault master password
- **WHEN** push or pull prompts for the sync host passphrase
- **THEN** the vault master password is not a valid substitute unless the user explicitly entered it as the sync passphrase during push

#### Scenario: Push records dual encryption
- **WHEN** push creates or replaces the host archive
- **THEN** the user has supplied the sync host passphrase used for that archive

### Requirement: Host archive artifact
The sync directory SHALL contain an outer ciphertext file (default `host.age`) that encrypts the packed vault snapshot using age **both** to the public key in the configured public file **and** with a scrypt passphrase layer using the sync host passphrase. Decryption SHALL require the matching sync private key **and** the correct sync host passphrase. The vault master password SHALL NOT decrypt `host.age`.

#### Scenario: Dual factor for host archive
- **WHEN** a user attempts pull with the private key but wrong sync host passphrase
- **THEN** decryption fails

#### Scenario: Dual factor missing key
- **WHEN** a user attempts pull with the correct sync host passphrase but without the private key
- **THEN** decryption fails

#### Scenario: Public git safe ciphertext
- **WHEN** only the host archive and plaintext public key file are published
- **THEN** opening the bundle still requires the sync private key and sync host passphrase; vault TOTP seeds and `nvlt.enc` remain absent from the sync directory

#### Scenario: Push and pull round-trip
- **WHEN** push then pull runs with the same keys, sync host passphrase, and path on a confirmed or empty vault root
- **THEN** recovered ciphertexts and config match the pushed snapshot aside from local-only `nvlt.enc`

### Requirement: Pull before migrate
After `sync pull`, the user SHALL run `init --migrate` to create local `nvlt.enc` using `lock` and ciphertexts from the pulled config and stores.

#### Scenario: Migrate uses pulled config
- **WHEN** the user runs `init --migrate` after a successful pull
- **THEN** migrate loads `lock` from `config.toml` and does not ask for a separate lock string unless config is missing or invalid
