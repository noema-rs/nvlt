## Purpose

Rate-limit unlock attempts on the operational machine using signed RT tokens paired one-to-one with local seed blobs, offline renewal, and recovery bundle material kept off the daily-use host.

## Requirements

### Requirement: Rate dupla layout
The vault root SHALL contain a `rate/` directory with exactly fifteen pairs named `01.rt` through `15.rt` and matching `01.enc` through `15.enc`. Each `.rt` file SHALL hold a minimal signed payload (slot, generation, device binding hash, and key material). Each `.enc` SHALL hold the same logical TOTP seed wrap as other slots in the generation but encrypted with a slot-specific key and SHALL record filesystem bind metadata (device, inode, size, content hash) captured at mint time in authenticated additional data.

#### Scenario: After init mint
- **WHEN** init or rate-limit renew completes
- **THEN** fifteen `.rt` and fifteen `.enc` files exist under `rate/` with private Unix permissions

### Requirement: One RT authorizes one auth attempt
The CLI SHALL select the lowest-numbered slot whose `.rt` is valid (signature verifies against configured rate-limit public key and filesystem bind matches its paired `.enc`). That slot SHALL authorize exactly one unlock attempt comprising master password, primary TOTP verification, and successful opening of vault ciphertext with the derived data key.

#### Scenario: Successful unlock
- **WHEN** password, TOTP, and vault decrypt succeed for slot k
- **THEN** slot k files remain valid for future unlocks

#### Scenario: Failed password
- **WHEN** master password does not unwrap the paired `.enc` for slot k
- **THEN** slot k `.rt` is invalidated so it no longer matches bind or signature checks and the attempt counts as consumed

#### Scenario: Failed TOTP
- **WHEN** password unwrap succeeds but primary TOTP code does not verify
- **THEN** slot k `.rt` is invalidated

#### Scenario: Failed vault decrypt
- **WHEN** password and TOTP verify but derived data key does not open `pass.age`
- **THEN** slot k `.rt` is invalidated

### Requirement: No valid RT blocks unlock
When no slot passes validation, the CLI SHALL refuse unlock and direct the user to `rate-limit renew` with offline recovery material.

#### Scenario: Exhausted generation
- **WHEN** all fifteen slots are invalid or missing
- **THEN** unlock fails without exposing seeds and the error mentions rate-limit renew

### Requirement: Rate-limit key pair
The system SHALL generate an Ed25519 rate-limit key pair at init. The public key SHALL be stored in vault config. The private key SHALL NOT be stored under the operational vault root after init completes.

#### Scenario: Pub in config
- **WHEN** init completes
- **THEN** config contains rate-limit public key and generation number starting at one

### Requirement: Recovery bundle
Init and rate-limit renew SHALL produce or update offline recovery bundle instructions for the user containing encrypted TOTP seed backup and the rate-limit private key, stored outside the daily-use machine. The operational vault SHALL NOT retain plaintext seeds or the rate-limit private key after setup.

#### Scenario: Bundle not on vault root
- **WHEN** init completes successfully
- **THEN** rate-limit private key is not present as a file under the vault root

### Requirement: Rate-limit renew
The CLI SHALL provide `nvlt rate-limit renew` accepting offline recovery bundle path and rate-limit private key path, verifying vault master password and primary TOTP, incrementing generation, removing prior `rate/` duplas, and minting fifteen new pairs.

#### Scenario: Renew after exhaustion
- **WHEN** renew succeeds with valid bundle, private key, and credentials
- **THEN** fifteen new valid duplas exist and unlock succeeds

#### Scenario: Renew denied without credentials
- **WHEN** password or TOTP fails during renew
- **THEN** existing rate files are not partially replaced
