## MODIFIED Requirements

### Requirement: Vault path layout
Configuration SHALL define vault root path and relative names for `pass.age`, `envs/`, `files/`, `totp.age`, `backup.age`, and the local seed blob `nvlt.enc`. Configuration SHALL include a string field `lock` used to derive the 16-byte KDF salt in memory on each operation. Configuration SHALL NOT use a separate `salt.bin` file or any other persisted salt file. Configuration SHALL allow optional sync artifact basenames for the host archive and public key used by `snapshot export` and `snapshot import`.

#### Scenario: Default layout
- **WHEN** no custom path is set
- **THEN** the default vault root is `~/.nvlt` with standard filenames including `nvlt.enc`

#### Scenario: Lock in config
- **WHEN** configuration is loaded for an initialized vault
- **THEN** `lock` is present and non-empty

#### Scenario: Salt never persisted
- **WHEN** any command derives vault keys
- **THEN** salt bytes are computed from `lock` in memory and are not read from or written to a salt file
