## ADDED Requirements

### Requirement: Derive KDF salt from lock string
The system SHALL expose a deterministic function that maps a user-facing `lock` string to exactly 16 bytes of salt suitable for Argon2id, using a fixed versioned algorithm documented for the product (for example HKDF-SHA256 with a constant domain label).

#### Scenario: Same lock same salt
- **WHEN** the same lock string is supplied twice
- **THEN** the derived 16-byte salt is identical

#### Scenario: Different lock different salt
- **WHEN** two distinct lock strings are supplied
- **THEN** the derived salts are not equal with overwhelming probability

#### Scenario: KDF integration
- **WHEN** vault key derivation runs for data or backup keys
- **THEN** the caller supplies salt bytes produced from the vault config `lock` field rather than reading a separate salt file
