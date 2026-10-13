## ADDED Requirements

### Requirement: Panic recovery path
Documentation and command output SHALL state that after `nvlt panic` the user restores ciphertext via `snapshot import` or an existing tree, then runs `nvlt init --from-snapshot` with vault credentials and mints new local rate duplas; offline recovery bundle and rate-limit key remain the user's responsibility off the machine.

#### Scenario: Documented flow
- **WHEN** a user reads INIT.md lifecycle section for panic
- **THEN** the from-snapshot path is described as the normal recovery after panic
