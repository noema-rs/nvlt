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

### Requirement: Interactive profile edit
The CLI SHALL provide `env edit <profile>` to set variables interactively (prompt for key and value until an empty key).

#### Scenario: Edit existing profile
- **WHEN** the user edits a profile and enters keys and values
- **THEN** the encrypted profile file is updated with the new variables

### Requirement: Import from env file
The CLI SHALL provide `env import <profile>` to merge variables from a dotenv-style file. When the file path is omitted, the CLI SHALL prompt for it interactively.

#### Scenario: Import merges keys
- **WHEN** import reads KEY=VALUE lines from the given file
- **THEN** each key is set on the profile and persisted encrypted

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
