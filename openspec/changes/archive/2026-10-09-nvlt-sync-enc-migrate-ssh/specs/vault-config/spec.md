## MODIFIED Requirements

### Requirement: Vault path layout
Configuration SHALL define vault root path and relative names for `pass.age`, `envs/`, `files/`, `totp.age`, `backup.age`, and the local seed blob `nvlt.enc`. Configuration SHALL include a string field `lock` used to derive the 16-byte KDF salt in memory on each operation. Configuration SHALL NOT use a separate `salt.bin` file or any other persisted salt file. Configuration SHALL allow optional sync artifact basenames for the host archive and public key used by `sync push` and `sync pull`.

#### Scenario: Default layout
- **WHEN** no custom path is set
- **THEN** the default vault root is `~/.nvlt` with standard filenames including `nvlt.enc`

#### Scenario: Lock in config
- **WHEN** configuration is loaded for an initialized vault
- **THEN** `lock` is present and non-empty

#### Scenario: Salt never persisted
- **WHEN** any command derives vault keys
- **THEN** salt bytes are computed from `lock` in memory and are not read from or written to a salt file

### Requirement: Two-tier configuration files
The CLI SHALL store a bootstrap pointer at `~/.config/nvlt/config.toml` containing at least `[vault] path`, and SHALL store the full configuration at `{vault.path}/config.toml` alongside encrypted vault data.

#### Scenario: First run
- **WHEN** the bootstrap file does not exist
- **THEN** the CLI creates it with the default vault path and creates `{vault.path}/config.toml` with default KDF, layout, and a newly generated `lock` on first init

#### Scenario: Load order
- **WHEN** any command loads configuration
- **THEN** it reads the bootstrap path, then loads or creates the vault-local `config.toml` under that directory

#### Scenario: Save
- **WHEN** the user runs `nvlt config set` or `nvlt config path`
- **THEN** changes are persisted to `{vault.path}/config.toml` and the bootstrap pointer is updated if `vault.path` changed

### Requirement: KDF parameters
Configuration SHALL expose Argon2id memory, time, and parallelism costs with defaults of 65536 KiB memory, 3 iterations, and 4 threads.

#### Scenario: Tunable costs
- **WHEN** KDF settings are changed in config
- **THEN** subsequent derive operations use the updated parameters with salt derived from the same `lock` value

## ADDED Requirements

### Requirement: Local encrypted TOTP seeds
The vault root SHALL contain `nvlt.enc`, a versioned encrypted blob holding primary and backup TOTP seeds wrapped with a key derived from the master password. The file SHALL use private filesystem permissions on Unix. It SHALL NOT be included in sync bundles or required in public repositories.

#### Scenario: After init
- **WHEN** `init` or successful `init --migrate` completes
- **THEN** `nvlt.enc` exists and no plaintext primary or backup seed files remain under the vault root

#### Scenario: Gitignore guidance
- **WHEN** documentation describes public git workflow
- **THEN** it lists `nvlt.enc` as local-only alongside sync private keys

## REMOVED Requirements

### Requirement: TOTP seed location
**Reason**: Primary and backup seeds are stored together in password-wrapped `nvlt.enc`; legacy keyring, plaintext file, and per-unlock seed prompt modes are removed.

**Migration**: Users re-run `init --migrate` with existing ciphertexts and seeds, or restore from sync extract then migrate; old `totp_seed_location` settings are ignored.
