# vault-panic Specification

## Purpose

Emergency destruction of local operational vault material when the user believes the host or local nvlt tree is compromised, with recovery expected from a git snapshot and the offline backup key stored elsewhere.

## Requirements

### Requirement: Panic command
The CLI SHALL provide `nvlt system panic` that removes operational encrypted vault files under the configured vault root (the `.age` files and encrypted stores such as `envs/` and `files/`), legacy `nvlt.enc` if present, and clears the agent session.

#### Scenario: Wipe ciphertext
- **WHEN** panic completes successfully on an initialized vault
- **THEN** `pass.age`, `totp.age`, `backup.age`, `ssh.age`, `envs/`, and `files/` are absent under the vault root

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
After a successful panic, the CLI SHALL remove `lock` from vault-local `config.toml` while preserving vault path and KDF settings.

#### Scenario: Status after panic
- **WHEN** the user runs `nvlt system status` after panic
- **THEN** the vault is reported as not initialized for unlock purposes

### Requirement: Recovery guidance
On successful panic, the CLI SHALL print a short message directing the user to restore via git snapshot and `nvlt system init --from-snapshot`, and to keep the offline backup key stored off the machine.

#### Scenario: Post-panic message
- **WHEN** panic succeeds
- **THEN** the output mentions from-snapshot and does not print secrets

### Requirement: Panic scope
Panic SHALL NOT delete snapshot repositories outside the configured vault root, unlock key files the user keeps elsewhere, or the offline backup key.

#### Scenario: External snapshot safe
- **WHEN** the user's git snapshot clone lives outside `vault.path`
- **THEN** panic does not remove those files

#### Scenario: Key files untouched
- **WHEN** the user stores unlock key files outside the vault root
- **THEN** panic does not remove them
