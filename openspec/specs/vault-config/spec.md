## Purpose

Describes configurable vault paths, KDF parameters, and where configuration files live on disk.
## Requirements
### Requirement: Vault path layout
Configuration SHALL define vault root path and relative names for `pass.age`, `envs/`, `files/`, `totp.age`, and `backup.age`. Configuration SHALL include a string field `lock` used to derive the 16-byte KDF salt in memory on each operation. Configuration SHALL NOT include `device_id`, rate-limit fields, rate generation counters, or any `rate/` directory. Configuration SHALL NOT use a separate `salt.bin` file or any other persisted salt file. Configuration SHALL allow optional sync artifact basenames for the host archive and public key used by `snapshot export` and `snapshot import`.

#### Scenario: Default layout
- **WHEN** no custom path is set
- **THEN** the default vault root is `~/.nvlt` with the standard store filenames and no `rate/` directory

#### Scenario: Lock in config
- **WHEN** configuration is loaded for an initialized vault
- **THEN** `lock` is present and non-empty

#### Scenario: Salt never persisted
- **WHEN** any command derives vault keys
- **THEN** salt bytes are computed from `lock` in memory and are not read from or written to a salt file

### Requirement: No key material in configuration
Configuration files SHALL NOT store unlock key paths, unlock key bytes, or device binding identifiers. Key paths are prompted visibly on every unlock and SHALL NOT be auto-discovered from config.

#### Scenario: No stored key path
- **WHEN** the user inspects `config.toml` after init or unlock
- **THEN** no unlock key path or key material is present

### Requirement: Two-tier configuration files
The CLI SHALL store a bootstrap pointer at `~/.config/nvlt/config.toml` containing at least `[vault] path`, and SHALL store the full configuration at `{vault.path}/config.toml` alongside encrypted vault data.

#### Scenario: First run
- **WHEN** the bootstrap file does not exist
- **THEN** the CLI creates it with the default vault path and creates `{vault.path}/config.toml` with default KDF, layout, and a newly generated `lock` on first init

#### Scenario: Load order
- **WHEN** any command loads configuration
- **THEN** it reads the bootstrap path, then loads or creates the vault-local `config.toml` under that directory

#### Scenario: Save
- **WHEN** the user runs `nvlt system config set` or `nvlt system config path`
- **THEN** changes are persisted to `{vault.path}/config.toml` and the bootstrap pointer is updated if `vault.path` changed

### Requirement: KDF parameters
Configuration SHALL expose Argon2id memory, time, and parallelism costs with defaults of 262144 KiB memory, 4 iterations, and 4 threads. These defaults are the offline-guessing brake for configurations where the key file resides on the same machine as the vault ciphertext.

#### Scenario: Tunable costs
- **WHEN** KDF settings are changed in config
- **THEN** subsequent derive operations use the updated parameters with salt derived from the same `lock` value

#### Scenario: Bumped defaults
- **WHEN** a new vault is initialized
- **THEN** the persisted KDF settings are 262144 KiB memory, 4 iterations, and 4 threads
