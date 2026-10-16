## Purpose

Manages standalone TOTP seeds for services without associated passwords, stored in encrypted `totp.age`.

## Requirements

### Requirement: Standalone entries
The system SHALL store entries uniquely keyed by `(site, account)` (CLI: issuer and name) with seed, algorithm, digits, and period in JSON version 1 inside `totp.age`. Multiple names for the same issuer SHALL be allowed. Seeds SHALL be normalized (trim, strip whitespace, uppercase base32) on add and get; invalid base32 SHALL be rejected on add. Short issuer secrets (e.g. 80-bit GitHub base32) SHALL be accepted when building TOTP (RFC minimum is not enforced at construction).

#### Scenario: Site without password entry
- **WHEN** a user adds a standalone TOTP for a site
- **THEN** codes are available via get without a password-manager entry for that site

#### Scenario: Multiple accounts per site
- **WHEN** a user adds two entries with the same site and different account labels
- **THEN** both entries persist and are addressable independently

### Requirement: CRUD and code display
The system SHALL support add, list, get (current code and time remaining), and remove with confirmation on remove. Get, remove, and export SHALL require both issuer and name arguments (stored as site and account).

#### Scenario: Get code
- **WHEN** get is invoked for an existing site and account
- **THEN** the current TOTP and seconds until rotation are shown

### Requirement: QR export and import
The system SHALL support exporting and importing TOTP configuration via QR or file for migration.

#### Scenario: Import
- **WHEN** import succeeds from a valid QR or file
- **THEN** a new or updated standalone entry is persisted encrypted
