## MODIFIED Requirements

### Requirement: Vault path layout
Configuration SHALL define vault root path and relative names for `pass.age`, `envs/`, `files/`, `totp.age`, `backup.age`, and the local rate directory `rate/` containing duplas instead of a single `nvlt.enc`. Configuration SHALL include a string field `lock` used to derive the 16-byte KDF salt in memory on each operation. Configuration SHALL include `device_id`, rate-limit public key (base64), and `rate_generation` after init. Configuration SHALL NOT use a separate `salt.bin` file or any other persisted salt file. Configuration SHALL allow optional sync artifact basenames for the host archive and public key used by `snapshot export` and `snapshot import`.

#### Scenario: Default layout
- **WHEN** no custom path is set
- **THEN** the default vault root is `~/.nvlt` with standard filenames including `rate/` duplas

#### Scenario: Lock in config
- **WHEN** configuration is loaded for an initialized vault
- **THEN** `lock` is present and non-empty

#### Scenario: Salt never persisted
- **WHEN** any command derives vault keys
- **THEN** salt bytes are computed from `lock` in memory and are not read from or written to a salt file

### Requirement: Local encrypted TOTP seeds
The vault root SHALL contain fifteen slot `.enc` files under `rate/` holding primary and backup TOTP seeds wrapped with keys derived from the master password and slot-specific rate material. Legacy single `nvlt.enc` SHALL NOT be used for new inits. The files SHALL use private filesystem permissions on Unix. They SHALL NOT be included in sync bundles or required in public repositories.

#### Scenario: After init
- **WHEN** `init` or successful `init --from-snapshot` completes
- **THEN** rate duplas exist and no plaintext primary or backup seed files remain under the vault root

#### Scenario: Gitignore guidance
- **WHEN** documentation describes public git workflow
- **THEN** it states that rate duplas and `nvlt.enc` if present are local-only and must not be committed
