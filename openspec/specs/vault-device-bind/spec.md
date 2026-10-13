## Purpose

Bind operational vault local unlock artifacts to the host machine so copied trees on other systems cannot unlock and mismatches trigger local wipe.

## Requirements

### Requirement: Device fingerprint
On Linux, the CLI SHALL compute a stable `device_id` as a hash of machine-id, DMI product UUID when available, and board serial when available, with a fixed domain separation string. The value SHALL be stored in vault config at init, init from snapshot, and rate-limit renew.

#### Scenario: Record at init
- **WHEN** init completes on a host
- **THEN** config contains the computed device_id for that host

### Requirement: Device check on local gate
Before rate dupla validation or seed unwrap, the CLI SHALL recompute device_id and compare to config. On mismatch, the CLI SHALL wipe operational vault content under the configured vault root (encrypted stores, rate directory, and local seed artifacts) and exit with an error that does not print secrets.

#### Scenario: Copied tree wrong host
- **WHEN** unlock runs and live device_id differs from config
- **THEN** local vault files under the root are removed and unlock does not proceed

#### Scenario: Same host
- **WHEN** device_id matches
- **THEN** rate validation proceeds normally

### Requirement: Device in recovery bundle
Offline recovery bundle ciphertext SHALL include device_id at mint time so renew on a different machine requires init from snapshot or new init rather than reusing bundle alone.

#### Scenario: Renew on same machine
- **WHEN** rate-limit renew runs and bundle device_id matches live device_id
- **THEN** mint proceeds

#### Scenario: Bundle device mismatch on renew
- **WHEN** bundle device_id differs from live device_id
- **THEN** renew fails without minting duplas
