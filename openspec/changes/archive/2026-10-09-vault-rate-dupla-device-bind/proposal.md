## Why

Local TOTP seeds in a single `nvlt.enc` can be brute-forced interactively without a hard attempt budget, and copying `~/.nvlt` to another machine reuses the same unlock path. We need device binding, offline recovery material, and rate-limit duplas (RT + enc pairs) so each failed auth consumes one signed attempt token while successful unlock does not.

## What Changes

- **BREAKING**: Replace single-file `nvlt.enc` password wrap with **15 duplas** under `rate/` (`NN.rt` + `NN.enc`), each authorizing one unlock attempt when filesystem binding matches.
- Add **device fingerprint** (`device_id`); mismatch on unlock or local gate SHALL wipe operational vault paths under the configured root.
- Add **Ed25519 rate-limit key pair**: public key in config; private key only in offline **recovery bundle** (never on the daily-use machine).
- **`rate-limit renew`**: mint new duplas using offline bundle + rate-limit private key + vault credentials.
- Unlock: validate RT (signature + bind vs paired `.enc` AAD), then master password, TOTP, and vault decrypt; **any failure burns the current RT** (mutate file); success does not burn.
- Update `init`, `init --from-snapshot`, `status`, and docs (README / INIT).

## Capabilities

### New Capabilities

- `vault-rate-limit`: RT/enc duplas, mint, verify, burn, renew, recovery bundle format.
- `vault-device-bind`: Linux device fingerprint, storage in config, mismatch wipe policy.

### Modified Capabilities

- `vault-lifecycle`: init / from-snapshot create duplas and device id; unlock flow uses rate gate before TOTP seeds.
- `vault-cli`: new `rate-limit renew` command; status shows rate generation and remaining slots.
- `vault-config`: fields for `device_id`, `rate_limit_pub`, `rate_generation`.

## Impact

- `cli/src/unlock.rs`, `cli/src/nvlt_enc.rs` (refactor or replace), new `cli/src/rate_limit.rs`, `cli/src/device.rs`, `cli/src/paths.rs`, `cli/src/lifecycle.rs`, `cli/src/config.rs`, `cli/src/main.rs`.
- New dependency: `ed25519-dalek` or `age` signing patterns; filesystem `stat` for bind.
- Migration: existing vaults with legacy `nvlt.enc` require `rate-limit renew` after upgrade or re-init from snapshot.

## Non-goals (this change)

- TPM / Secure Enclave integration.
- `rebind` command for hardware changes (document wipe + from-snapshot instead).
- Including rate-limit private key or plaintext recovery bundle on the operational OS disk.
