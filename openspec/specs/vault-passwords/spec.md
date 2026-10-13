## Purpose

Stores and manages website credentials keyed by domain and username, with optional embedded TOTP and flexible extra fields, persisted in encrypted `pass.age`.

## Requirements

### Requirement: Unique entry identity
The system SHALL treat `(domain, username)` as the unique key for a password entry within the vault.

#### Scenario: Duplicate add
- **WHEN** a user attempts to add an entry whose domain and username already exist
- **THEN** the operation fails with a clear error

### Requirement: CRUD with confirmation on destructive changes
The system SHALL support search, list, get, add, edit, and remove. Edit and remove SHALL require explicit user confirmation describing the entry affected.

#### Scenario: Remove confirmation
- **WHEN** the user invokes remove for an existing entry
- **THEN** the CLI shows domain and username and requires affirmative confirmation before deletion

### Requirement: Flexible fields and embedded TOTP
The system SHALL support entries that include password, notes, optional TOTP parameters (seed, algorithm, digits, period), and optional key-value `fields` for PINs, recovery codes, or similar.

#### Scenario: Get with TOTP
- **WHEN** the user retrieves an entry with embedded TOTP
- **THEN** the output includes the current TOTP code and remaining validity time

### Requirement: Encrypted persistence
The system SHALL serialize entries as JSON version 2 and persist only as age-encrypted `pass.age` using the vault data key.

#### Scenario: Persist after mutation
- **WHEN** an entry is added or updated successfully
- **THEN** `pass.age` on disk reflects the change and remains encrypted
