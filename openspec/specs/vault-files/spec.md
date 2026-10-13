## Purpose

Encrypts arbitrary user files into the vault `files/` store and decrypts them to a path or stdout.

## Requirements

### Requirement: Encrypt to vault store
The system SHALL read a user file, encrypt bytes with the data key, and store under `files/` using the source basename unless configured otherwise.

#### Scenario: Encrypt confirmation
- **WHEN** encrypt is invoked
- **THEN** the user must confirm source path, destination in vault, and overwrite behavior if a name collision exists

### Requirement: Decrypt to path or stdout
The system SHALL decrypt a stored file to a user-specified path or to stdout when requested.

#### Scenario: Decrypt overwrite
- **WHEN** decrypt targets an existing path
- **THEN** the user must confirm overwrite before writing plaintext

### Requirement: List and remove
The system SHALL list encrypted filenames and remove entries with confirmation.

#### Scenario: Remove encrypted file
- **WHEN** remove is confirmed
- **THEN** the encrypted blob is deleted from `files/`
