## MODIFIED Requirements

### Requirement: Initialize new vault
The system SHALL create empty encrypted stores (`pass.age`, `envs/`, `files/`, `totp.age`), empty `backup.age`, a new random `lock` value in config, device fingerprint, rate-limit public key and generation, fifteen rate duplas under `rate/` holding verified primary and backup TOTP seeds, and offline recovery bundle output for the user. Init SHALL verify both authenticators with 6-digit codes before writing encrypted data.

#### Scenario: Init
- **WHEN** init completes successfully
- **THEN** all paths exist under the configured vault directory, `lock` is set, rate duplas exist, and no plaintext TOTP seeds are written to disk except optional QR or display during setup

#### Scenario: Init QR outputs
- **WHEN** init completes successfully
- **THEN** the CLI MAY write QR PNGs under the vault root for scanning into an authenticator app

#### Scenario: Init TOTP verification
- **WHEN** init is setting up authenticators
- **THEN** the CLI generates or accepts primary material, verifies the user’s app code, then does the same for backup before creating encrypted vault files and rate duplas

#### Scenario: Init progress feedback
- **WHEN** init is running setup steps
- **THEN** the CLI prints short status lines so the user knows what is in progress

#### Scenario: Init ASCII QR
- **WHEN** init displays setup material for primary and backup seeds
- **THEN** the CLI MAY print otpauth URIs and ASCII QR codes in the terminal

#### Scenario: Init blocked when salt exists
- **WHEN** `init` is invoked without `--from-snapshot` and the vault is already initialized (for example `lock` is set and core stores exist)
- **THEN** init fails with a message that names the vault path and warns that re-init causes data loss without password, seeds, or backup, and directs the user to `init --from-snapshot` or recover

#### Scenario: Init blocked when vault exists
- **WHEN** `init` is invoked without `--from-snapshot` and encrypted stores already exist under the configured vault root
- **THEN** init fails and does not overwrite existing ciphertext

### Requirement: Unlock flow for daily use
Each command that accesses encrypted data SHALL verify device binding, validate the lowest available rate dupla, prompt for master password and primary TOTP code unless a valid agent session exists, unwrap seeds from the paired slot `.enc`, verify the code, derive the data key using salt from `lock`, re-wrap the slot `.enc` after successful seed use, and clear secrets when finished. Any failed password, TOTP, or vault decrypt after selecting a slot SHALL invalidate that slot’s `.rt`.

#### Scenario: Failed unlock
- **WHEN** password or TOTP verification fails after a rate slot was consumed for the attempt
- **THEN** no plaintext vault content is exposed, the slot `.rt` is invalidated, and other vault ciphertext files are not modified except the invalidated rate artifacts

#### Scenario: No seed text prompt on unlock
- **WHEN** unlock runs and rate duplas are present
- **THEN** the CLI does not ask for the primary seed string

### Requirement: Init from snapshot
The CLI SHALL support `nvlt init --from-snapshot --path <directory>` with optional `--identity <path>` to the sync age private key (default `{path}/.nvlt-sync/host.key`). The command SHALL prompt for the sync host passphrase, decrypt and extract the snapshot into the vault root, reload configuration including `lock`, then prompt for vault master password, primary and backup TOTP seeds, and 6-digit codes, verify decrypt of existing ciphertext, and mint new device binding and rate duplas for this host.

#### Scenario: New machine bootstrap
- **WHEN** the user runs `init --from-snapshot` with valid snapshot and vault credentials
- **THEN** vault files and rate duplas exist locally and unlock succeeds

#### Scenario: Missing identity
- **WHEN** the sync private key is missing at the resolved identity path
- **THEN** the command fails with a clear error and does not generate a new sync keypair

#### Scenario: Failed proof decrypt
- **WHEN** vault credentials do not decrypt imported ciphertext
- **THEN** the command fails, does not write rate duplas, and leaves imported files unchanged unless extraction already completed (user must re-import)

#### Scenario: Replace nvlt.enc
- **WHEN** rate duplas already exist
- **THEN** the user MUST confirm before replacing them after successful proof decrypt

#### Scenario: Missing config lock after extract
- **WHEN** extracted `config.toml` has no `lock` field
- **THEN** the command fails before minting rate duplas

### Requirement: Reveal TOTP seed
The CLI SHALL expose `nvlt reveal primary` and `nvlt reveal backup` which verify device binding and a valid rate dupla, accept master password and the corresponding 6-digit TOTP code, then print the seed or otpauth URI once to stdout after successful verification.

#### Scenario: Reveal primary
- **WHEN** `nvlt reveal primary` succeeds
- **THEN** the seed or uri is printed to stdout and not written to disk by default

#### Scenario: Reveal denied on bad code
- **WHEN** the TOTP code does not match
- **THEN** no seed material is printed and the rate slot used for the attempt is invalidated
