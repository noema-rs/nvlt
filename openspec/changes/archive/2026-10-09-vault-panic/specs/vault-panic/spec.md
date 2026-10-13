## Purpose

Emergency destruction of local operational vault material when the user believes the host or local nvlt tree is compromised, with recovery expected from snapshot and offline bundle stored elsewhere.

## ADDED Requirements

### Requirement: Panic command
The CLI SHALL provide `nvlt panic` that removes operational encrypted vault files under the configured vault root, the entire `rate/` directory, legacy `nvlt.enc` if present, and clears the agent session.

#### Scenario: Wipe ciphertext
- **WHEN** panic completes successfully on an initialized vault
- **THEN** `pass.age`, `totp.age`, `backup.age`, `ssh.age`, `envs/`, `files/`, and `rate/` are absent under the vault root

#### Scenario: Agent cleared
- **WHEN** panic runs
- **THEN** any cached unlock agent session for the vault is cleared

### Requirement: Panic confirmation
Panic SHALL require the user to type the exact token `PANIC` and to confirm a destructive prompt defaulting to no before any file is removed.

#### Scenario: Cancelled panic
- **WHEN** the user does not type `PANIC` or declines confirmation
- **THEN** no files are removed and config is unchanged

### Requirement: Panic authentication
When `pass.age` exists, panic SHALL require the vault master password and SHALL verify it by successfully deriving the data key against `pass.age` before wiping. When the vault is not initialized, panic MAY skip password verification.

#### Scenario: Wrong password
- **WHEN** the master password does not open `pass.age`
- **THEN** panic aborts with no file removal

### Requirement: Config reset after panic
After a successful panic, the CLI SHALL remove `lock`, `device_id`, `rate_limit_pub`, and `rate_generation` from vault-local `config.toml` while preserving vault path and KDF settings.

#### Scenario: Status after panic
- **WHEN** the user runs `nvlt status` after panic
- **THEN** the vault is reported as not initialized for unlock purposes

### Requirement: Recovery guidance
On successful panic, the CLI SHALL print a short message directing the user to restore via git snapshot and `nvlt init --from-snapshot`, and to use offline recovery bundle material stored off the machine.

#### Scenario: Post-panic message
- **WHEN** panic succeeds
- **THEN** the output mentions from-snapshot and does not print secrets

### Requirement: Panic scope
Panic SHALL NOT delete snapshot repositories outside the configured vault root or modify offline recovery bundle files the user keeps elsewhere.

#### Scenario: External snapshot safe
- **WHEN** the user's git snapshot clone lives outside `vault.path`
- **THEN** panic does not remove those files
