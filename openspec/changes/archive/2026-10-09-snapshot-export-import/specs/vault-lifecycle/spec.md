## MODIFIED Requirements

### Requirement: Init migrate
The CLI SHALL support `init --migrate` for vault directories that already contain encrypted stores and `config.toml` (typically after `snapshot import`) but may lack `nvlt.enc`. Migrate SHALL read `lock` from config, derive KDF salt only in memory, prompt for master password, primary and backup TOTP seeds, and 6-digit codes for both seeds, then SHALL verify that derived keys decrypt existing ciphertext before writing `nvlt.enc`.

#### Scenario: Successful migrate
- **WHEN** the user supplies correct password, seeds, and codes for existing `.age` files and config contains a valid `lock`
- **THEN** migrate writes `nvlt.enc` and reports success without re-encrypting all stores unnecessarily

#### Scenario: Failed proof decrypt
- **WHEN** credentials do not decrypt existing data
- **THEN** migrate fails, does not write `nvlt.enc`, and leaves existing ciphertext unchanged

#### Scenario: Migrate not for empty vault
- **WHEN** `init --migrate` runs on a directory with no encrypted vault stores
- **THEN** the command fails and directs the user to plain `init`

#### Scenario: Missing config lock
- **WHEN** `init --migrate` runs and `config.toml` has no `lock` field
- **THEN** migrate fails with a clear error directing the user to fix config or run `snapshot import`
