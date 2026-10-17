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

### Requirement: Export to file
The CLI SHALL write dotenv-style `KEY="value"` lines to a user-supplied file path for a profile, confirming before overwriting an existing file.

#### Scenario: Export format
- **WHEN** export is invoked for a profile with variables and a destination path
- **THEN** each variable appears as a valid dotenv line in the written file

### Requirement: Load into shell
The CLI SHALL provide `env load` that prints shell `export KEY="value"` lines to stdout when stdout is not a terminal (for `eval`), and SHALL provide `env hook` that prints a shell function intercepting `env load` in interactive shells.

#### Scenario: Hook install
- **WHEN** the user evaluates `nvlt env hook` in bash or zsh
- **THEN** subsequent `nvlt env load <profile>` calls set variables in the current shell

### Requirement: Profile removal
Removing a profile SHALL require confirmation and delete the profile's encrypted file.

#### Scenario: Remove profile
- **WHEN** the user confirms profile removal
- **THEN** the profile file is deleted and variables are no longer accessible
