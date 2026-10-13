## Purpose

Provides the shared cryptographic engine for Vault: slow key derivation, age encryption, TOTP verification, and safe handling of secrets in memory.
## Requirements
### Requirement: Derive data key from password and TOTP seed
The system SHALL derive a 32-byte key using Argon2id from the concatenation of the master password and the primary TOTP seed, with a caller-supplied salt and parameters defaulting to 64 MiB memory, 3 iterations, and 4 parallelism lanes.

#### Scenario: Deterministic derivation
- **WHEN** the same password, seed, salt, and KDF parameters are supplied
- **THEN** the derived key bytes are identical on every invocation

#### Scenario: Distinct inputs produce distinct keys
- **WHEN** only the password or only the seed differs, with the same salt and parameters
- **THEN** the derived keys are not equal

### Requirement: Encrypt and decrypt with age
The system SHALL encrypt arbitrary plaintext to ciphertext and decrypt back to the original plaintext using the derived 32-byte key passed to age as secret key material.

#### Scenario: Round-trip
- **WHEN** plaintext is encrypted with a derived key and then decrypted with the same key
- **THEN** the recovered bytes equal the original plaintext

#### Scenario: Wrong key fails decrypt
- **WHEN** ciphertext is decrypted with a different derived key than was used to encrypt
- **THEN** decryption fails without returning plaintext

### Requirement: Verify TOTP code against seed
The system SHALL verify a user-supplied 6-digit TOTP code against the primary TOTP seed without using the rotating code as KDF input.

#### Scenario: Valid code
- **WHEN** the code matches the current time step for the seed
- **THEN** verification succeeds

#### Scenario: Invalid code
- **WHEN** the code does not match the current time step for the seed
- **THEN** verification fails

### Requirement: Generate current TOTP code
The system SHALL generate the current TOTP code for a given seed using the configured algorithm, digit count, and period.

#### Scenario: Code generation
- **WHEN** a valid seed is provided
- **THEN** a numeric code of the configured length is returned

### Requirement: Protect secrets in memory
The system SHALL accept and return master password, seeds, and derived keys through opaque secret types that zeroize backing memory on drop.

#### Scenario: Secret lifecycle
- **WHEN** a secret value is no longer needed
- **THEN** the implementation clears the buffer before deallocation

### Requirement: Surface typed errors
The system SHALL report KDF, encryption, decryption, and TOTP failures through a structured error type suitable for propagation from library crates.

#### Scenario: KDF failure
- **WHEN** key derivation cannot complete
- **THEN** the caller receives an error indicating KDF failure without secret material in the message

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

