## Purpose

Covers vault initialization, status, backup, recovery, and credential rotation with main and backup unlock keys.
## Requirements
### Requirement: Initialize new vault
The system SHALL create empty encrypted stores (`pass.age`, `envs/`, `files/`, `totp.age`), empty `backup.age`, and a new random `lock` value in config. Init SHALL generate a main unlock keypair and a backup unlock keypair (age X25519), prompt visibly for a main key file path and a backup key file path, write both key files with private filesystem permissions on Unix, and print offline-storage instructions requiring the backup key to be stored strictly off the machine. Init SHALL NOT mint rate duplas, device registration material, a recovery bundle, or any auth TOTP seeds.

#### Scenario: Init
- **WHEN** init completes successfully
- **THEN** all stores exist under the configured vault directory, `lock` is set, both key files exist at the prompted paths, no `rate/` directory exists, and no recovery bundle is produced

#### Scenario: Init progress feedback
- **WHEN** init is running setup steps
- **THEN** the CLI prints short status lines so the user knows what is in progress

#### Scenario: Init backup key instructions
- **WHEN** init completes successfully
- **THEN** the output instructs the user to store the backup key strictly offline and states that it is required for `backup` and `recover`

#### Scenario: Init blocked when vault exists
- **WHEN** `nvlt system init` is invoked without `--from-snapshot` and the vault is already initialized (for example `lock` is set and core stores exist)
- **THEN** init fails with a message that names the vault path and warns that re-init causes data loss without password, keys, or backup, and directs the user to `init --from-snapshot` or recover

#### Scenario: Init blocked when ciphertext exists
- **WHEN** `nvlt system init` is invoked without `--from-snapshot` and encrypted stores already exist under the configured vault root
- **THEN** init fails and does not overwrite existing ciphertext

### Requirement: Backup sync
The system SHALL decrypt all data-key-protected content and re-encrypt a copy into `backup.age` using a key derived from the backup unlock key through the KDF chain with the master password, without including unlock key material in the backup payload. Backup SHALL prompt for the master password and for the backup key file path (visible prompt), never for pasted key bytes.

#### Scenario: Backup overwrite
- **WHEN** backup runs
- **THEN** the user confirms overwrite of existing `backup.age` before write

#### Scenario: Backup authorized by backup key
- **WHEN** backup runs with the wrong backup key file or a wrong master password
- **THEN** no `backup.age` is written

### Requirement: Recover from backup
The system SHALL restore data from `backup.age` using the master password and the backup unlock key, MAY issue a new main unlock key to replace a lost or compromised one, re-encrypt all data files under the restored or new data key, and invalidate the old main key.

#### Scenario: Recover confirmation
- **WHEN** recover is invoked
- **THEN** the user confirms replacement of current vault files before proceeding

#### Scenario: Recover issues new main key
- **WHEN** recover completes with a newly issued main unlock key
- **THEN** the old main key no longer opens the vault and the new key file path is prompted visibly

### Requirement: Rotate credentials
The system SHALL optionally change the master password and SHALL optionally generate new main and/or new backup unlock keys, re-encrypt all vault files and backup, and invalidate old credentials after confirmed rotation.

#### Scenario: Rotate
- **WHEN** rotation completes
- **THEN** unlock with the old password or old key files fails, and any newly generated key files exist only at the visibly prompted paths

### Requirement: Unlock flow for daily use
Each command that accesses encrypted data SHALL prompt for the master password (hidden) and the unlock key path (visible) unless a valid agent session exists, derive the data key through the KDF chain using salt from `lock`, apply the key custody warning when the key path is under the vault root or on the vault filesystem, and clear secrets when finished. Failed password, key, or vault decrypt attempts SHALL NOT expose plaintext and SHALL NOT modify vault ciphertext.

#### Scenario: Failed unlock
- **WHEN** the master password, the key file content, or the key passphrase is wrong
- **THEN** no plaintext vault content is exposed and no vault ciphertext files are modified

#### Scenario: No auto-discovery
- **WHEN** unlock runs without a valid agent session
- **THEN** the key path is prompted visibly every time and is never inferred from config or previous use

#### Scenario: Prompts only on first unlock
- **WHEN** a valid agent session exists
- **THEN** the password and key path prompts are skipped until idle timeout or `nvlt lock`

### Requirement: Init from snapshot
The CLI SHALL support `nvlt system init --from-snapshot --path <directory>` with optional `--identity <path>` to the sync age private key (default `{path}/.nvlt-sync/host.key`). The command SHALL prompt for the sync host passphrase, decrypt and extract the snapshot into the vault root, reload configuration including `lock`, then prompt for the vault master password and the main unlock key path (visible), and verify decrypt of existing ciphertext before declaring the vault initialized. Snapshot import SHALL NOT create device binding material or rate artifacts, and SHALL NOT generate a new main key silently.

#### Scenario: New machine bootstrap
- **WHEN** the user runs `init --from-snapshot` with valid snapshot, master password, and main unlock key
- **THEN** vault files exist locally and unlock succeeds

#### Scenario: Missing identity
- **WHEN** the sync private key is missing at the resolved identity path
- **THEN** the command fails with a clear error and does not generate a new sync keypair

#### Scenario: Failed proof decrypt
- **WHEN** the master password and main unlock key do not decrypt imported ciphertext
- **THEN** the command fails, does not modify imported files beyond the completed extraction, and directs the user to recover with the backup key if the main key is lost

#### Scenario: Missing config lock after extract
- **WHEN** extracted `config.toml` has no `lock` field
- **THEN** the command fails before declaring the vault initialized

### Requirement: Panic recovery path
Documentation and command output SHALL state that after `nvlt system panic` the user restores ciphertext via `snapshot import` or an existing tree, then runs `nvlt system init --from-snapshot` and unlocks with the master password and main unlock key (or recovers with the backup key if the main key is lost); the offline backup key remains the user's responsibility off the machine.

#### Scenario: Documented flow
- **WHEN** a user reads INIT.md lifecycle section for panic
- **THEN** the from-snapshot path is described as the normal recovery after panic, with the backup key stored offline as the fallback
