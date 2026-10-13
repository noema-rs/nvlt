## MODIFIED Requirements

### Requirement: Subcommand structure
The binary **`nvlt`** SHALL expose subcommands `pass`, `env`, `files`, `totp`, `ssh`, `config`, and top-level `init`, `status`, `unlock`, `lock`, `backup`, `recover`, `rotate`, **`snapshot`** (with `export` and `import`), **`rate-limit`** (with `renew`), and **`reveal`**. Init SHALL accept **`--from-snapshot --path`** and optional **`--identity`** for bootstrapping from a host archive. Init SHALL NOT expose `--migrate`. Documentation in INIT.md SHALL use the `nvlt` name and snapshot commands.

#### Scenario: Init help
- **WHEN** the user runs `nvlt init --help`
- **THEN** `--from-snapshot` and `--identity` are listed

#### Scenario: Help
- **WHEN** the user runs the binary with `--help`
- **THEN** all subsystems, lifecycle commands, `snapshot`, `rate-limit`, and `ssh` are listed

### Requirement: Session agent
On Unix, the CLI SHALL support `nvlt unlock --for <duration>` to cache the derived data key in a local agent process with a sliding idle timeout, and `nvlt lock` to clear it. Routine subcommands SHALL reuse the agent session when the vault path matches. Unlock SHALL complete rate dupla and device checks before caching a session.

#### Scenario: Unlock for ten minutes
- **WHEN** the user runs `nvlt unlock --for 10m` and completes password and authenticator verification
- **THEN** subsequent data commands skip unlock prompts until idle timeout or `nvlt lock`

#### Scenario: Agent status
- **WHEN** the user runs `nvlt status`
- **THEN** agent lock state, remaining idle time, rate generation, and count of valid rate slots are shown when available

## ADDED Requirements

### Requirement: Rate-limit renew command
The CLI SHALL implement `nvlt rate-limit renew` with required `--bundle` and `--rate-limit-key` paths, prompting for master password and primary TOTP before minting a new generation of duplas.

#### Scenario: Renew help
- **WHEN** the user runs `nvlt rate-limit renew --help`
- **THEN** required bundle and rate-limit key flags are documented
