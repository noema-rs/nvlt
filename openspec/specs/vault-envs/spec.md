## Purpose

Manages named environment-variable profiles, one encrypted file per profile, with granular CLI operations and stdout export.

## Requirements

### Requirement: One file per profile
The system SHALL store each profile as `envs/<profile>.age` containing JSON version 1 with profile name and key-value vars.

#### Scenario: Create profile
- **WHEN** the user adds a new profile or sets a key on a nonexistent profile
- **THEN** a new encrypted profile file is created

### Requirement: Granular variable operations
The system SHALL support listing profiles, listing keys in a profile, get, set, and unset for individual keys.

#### Scenario: Unset confirmation
- **WHEN** the user unsets a key
- **THEN** the CLI requires explicit confirmation naming profile and key

### Requirement: Export to stdout
The system SHALL print shell `export KEY="value"` lines to stdout for a profile without writing plaintext files itself.

#### Scenario: Export format
- **WHEN** export is invoked for a profile with variables
- **THEN** each variable appears as a valid export statement on stdout

### Requirement: Profile removal
Removing a profile SHALL require confirmation and delete the profile's encrypted file.

#### Scenario: Remove profile
- **WHEN** the user confirms profile removal
- **THEN** the profile file is deleted and variables are no longer accessible
