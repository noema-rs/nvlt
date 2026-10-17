# vault-ssh Specification

## Purpose
Lets users store SSH keypairs inside the encrypted vault, register them by unique name, and temporarily install or remove key material under the user’s `~/.ssh` directory for sessions.
## Requirements
### Requirement: SSH key registry
The system SHALL persist SSH entries in a vault store (for example `ssh.age`) keyed by a unique user-chosen **name**. Each entry SHALL store the private key material and MAY optionally store an OpenSSH public key. Register SHALL prompt interactively for the private key file path (visible echo). The public key SHALL be stored only when the user passes `--public`, which triggers a separate prompt for the public key file path. Key paths SHALL NOT be required as command-line arguments.

#### Scenario: Register private key only
- **WHEN** the user runs `ssh add <name>` without `--public`
- **THEN** only the private key is encrypted and listed under that name

#### Scenario: Register with optional public key
- **WHEN** the user runs `ssh add <name> --public` and supplies both prompted paths
- **THEN** private and public key material are stored encrypted under that name

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
The CLI SHALL support activating a registered name by writing the private key into `~/.ssh/{name}` with mode `600`. When a public key is stored, activate SHALL also write `~/.ssh/{name}.pub`. Deactivate SHALL remove only the paths recorded for that activation.

#### Scenario: Activate private-only entry
- **WHEN** the user activates a name with no stored public key
- **THEN** only the private key file appears under `~/.ssh` with correct permissions

#### Scenario: Activate with public key
- **WHEN** the user activates a name that includes a stored public key
- **THEN** both `{name}` and `{name}.pub` appear under `~/.ssh` with correct permissions

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
