## Purpose

Manages standalone TOTP seeds for services without associated passwords, stored in encrypted `totp.age`.

## Requirements

### Requirement: Standalone entries
The system SHALL store entries keyed by site with account label, seed, algorithm, digits, and period in JSON version 1 inside `totp.age`.

#### Scenario: Site without password entry
- **WHEN** a user adds a standalone TOTP for a site
- **THEN** codes are available via get without a password-manager entry for that site

### Requirement: CRUD and code display
The system SHALL support add, list, get (current code and time remaining), and remove with confirmation on remove.

#### Scenario: Get code
- **WHEN** get is invoked for an existing site
- **THEN** the current TOTP and seconds until rotation are shown

### Requirement: QR export and import
The system SHALL support exporting and importing TOTP configuration via QR or file for migration.

#### Scenario: Import
- **WHEN** import succeeds from a valid QR or file
- **THEN** a new or updated standalone entry is persisted encrypted
