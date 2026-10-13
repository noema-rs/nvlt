## Purpose

Lets users store SSH keypairs inside the encrypted vault, register them by unique name, and temporarily install or remove key material under the user’s `~/.ssh` directory for sessions.

## ADDED Requirements

### Requirement: SSH key registry
The system SHALL persist SSH keypairs as encrypted entries in a vault store (for example `ssh.age`) keyed by a unique user-chosen **name**. Each entry SHALL record enough metadata to reinstall the same files on activate and to remove only nvlt-managed paths on deactivate.

#### Scenario: Register from path
- **WHEN** the user runs register with a name and a filesystem path to a private key (and optional public key path)
- **THEN** the key material is encrypted with the vault data key and listed under that name

#### Scenario: Duplicate name rejected
- **WHEN** register is invoked with a name that already exists
- **THEN** the operation fails without overwriting the existing entry

### Requirement: SSH list and remove
The CLI SHALL list registered SSH entries by name and SHALL allow removing an entry from the vault store with confirmation.

#### Scenario: List names
- **WHEN** the user lists SSH entries
- **THEN** only names and non-secret metadata are shown

#### Scenario: Remove entry
- **WHEN** the user confirms removal of a name
- **THEN** the encrypted entry is deleted and any active installation for that name is deactivated first

### Requirement: Activate and deactivate in ssh directory
The CLI SHALL support activating a registered name by writing or linking key files into `~/.ssh` with mode `600` for private keys and `644` for public keys, using deterministic filenames derived from the entry name unless configured otherwise. Deactivate SHALL remove only the paths recorded for that activation.

#### Scenario: Activate installs keys
- **WHEN** the user activates a registered name
- **THEN** the corresponding key files appear under `~/.ssh` with correct permissions

#### Scenario: Deactivate cleans nvlt paths only
- **WHEN** the user deactivates a name
- **THEN** only files created or tracked by nvlt for that name are removed from `~/.ssh`

#### Scenario: Double activate
- **WHEN** the user activates a name that is already active
- **THEN** the command succeeds idempotently or reports already active without duplicating files

### Requirement: SSH open helper
The CLI SHALL expose an `open` (or equivalent) subcommand that activates a named entry and prints a suggested `ssh` invocation when the entry stores optional `host` and `user` fields.

#### Scenario: Open with stored host
- **WHEN** open is invoked for an entry with host metadata
- **THEN** the user receives a ready-to-run ssh command line using the activated key paths
