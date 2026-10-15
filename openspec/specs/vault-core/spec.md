## Purpose

Provides the shared cryptographic engine for Vault: the password-over-key KDF chain, age encryption, unlock key handling, TOTP codes for site seeds, and safe handling of secrets in memory.
## Requirements
### Requirement: Derive data key through KDF chain
The system SHALL derive a 32-byte data key through a sequential KDF chain that requires BOTH the master password and the private key secret: the password layer SHALL be applied over the key layer using Argon2id with caller-supplied salt and parameters defaulting to 262144 KiB memory, 4 iterations, and 4 parallelism lanes. Knowledge of the master password alone SHALL NOT yield usable key material, and knowledge of the key file alone SHALL NOT without passing the Argon2id cost per password guess.

#### Scenario: Deterministic derivation
- **WHEN** the same password, key secret, salt, and KDF parameters are supplied
- **THEN** the derived key bytes are identical on every invocation

#### Scenario: Both factors required
- **WHEN** derivation is attempted with only the master password or with only the key secret
- **THEN** no data key is produced

#### Scenario: Distinct inputs produce distinct keys
- **WHEN** only the password, only the key secret, only the salt, or only the parameters differ
- **THEN** the derived keys are not equal

### Requirement: Load unlock key from age identity file
The system SHALL read unlock key material from an age X25519 identity file at a caller-supplied path, parse the `AGE-SECRET-KEY-1…` secret, and expose its bytes as zeroizable secret material for the KDF chain. Malformed or corrupted key files SHALL fail with a structured error that contains no key material.

#### Scenario: Valid identity file
- **WHEN** a well-formed age identity file is supplied
- **THEN** the key secret is available to the KDF chain and the corresponding `age1…` public key can be derived

#### Scenario: Corrupted key file
- **WHEN** the file content fails encoding or checksum validation
- **THEN** derivation fails with a structured error and no key bytes are exposed

#### Scenario: Missing key file
- **WHEN** the supplied path does not exist
- **THEN** the caller receives a path-specific error without attempting derivation

### Requirement: Optional key file passphrase wrap
The system SHALL support at-rest encryption of a key file with a separate passphrase using an age scrypt passphrase layer, decrypted in memory on use. The wrap passphrase SHALL NOT be the master password and SHALL NOT participate in the KDF chain.

#### Scenario: Wrapped key file
- **WHEN** a wrapped key file is supplied at unlock
- **THEN** the CLI prompts for the key passphrase and decryption of the key file happens in memory only

#### Scenario: Wrong key passphrase
- **WHEN** the supplied key passphrase does not unwrap the key file
- **THEN** the command fails without exposing key bytes

### Requirement: Encrypt and decrypt with age
The system SHALL encrypt arbitrary plaintext to ciphertext and decrypt back to the original plaintext using the derived 32-byte key passed to age as secret key material.

#### Scenario: Round-trip
- **WHEN** plaintext is encrypted with a derived key and then decrypted with the same key
- **THEN** the recovered bytes equal the original plaintext

#### Scenario: Wrong key fails decrypt
- **WHEN** ciphertext is decrypted with a different derived key than was used to encrypt
- **THEN** decryption fails without returning plaintext

### Requirement: Verify TOTP code against seed
The system SHALL verify a user-supplied 6-digit TOTP code against a site seed without using the rotating code as KDF input. TOTP codes SHALL NOT participate in unlocking the vault.

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
The system SHALL accept and return master password, key secrets, wrap passphrases, site seeds, and derived keys through opaque secret types that zeroize backing memory on drop.

#### Scenario: Secret lifecycle
- **WHEN** a secret value is no longer needed
- **THEN** the implementation clears the buffer before deallocation

### Requirement: Surface typed errors
The system SHALL report KDF, encryption, decryption, key file, and TOTP failures through a structured error type suitable for propagation from library crates.

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
- **WHEN** vault key derivation runs through the KDF chain
- **THEN** the caller supplies salt bytes produced from the vault config `lock` field rather than reading a separate salt file
