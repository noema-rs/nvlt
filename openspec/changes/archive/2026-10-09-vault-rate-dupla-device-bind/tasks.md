## 1. Core modules

- [x] 1.1 Add `device.rs`: Linux fingerprint → `device_id` (blake3)
- [x] 1.2 Add `rate_limit.rs`: keygen, sign/verify RT, bind, mint duplas, burn, renew, bundle encrypt/decrypt
- [x] 1.3 Extend `VaultLayout` + config for `device_id`, `rate_limit_pub`, `rate_generation`, `rate/` paths
- [x] 1.4 Add `wipe.rs` for device mismatch

## 2. Lifecycle integration

- [x] 2.1 Init: device id, rate keys, mint duplas, write recovery bundle to user path
- [x] 2.2 `init --from-snapshot`: mint duplas after proof decrypt
- [x] 2.3 Replace `unlock.rs` / `nvlt_enc.rs` usage with rate gate + slot enc unwrap
- [x] 2.4 Update backup/recover/rotate/reveal paths that used `nvlt.enc`
- [x] 2.5 `rate-limit renew` command in `main.rs` / `commands.rs`

## 3. UX and docs

- [x] 3.1 `status`: generation + valid slot count
- [x] 3.2 Legacy `nvlt.enc` detection message
- [x] 3.3 Update INIT.md and README.md sections for rate duplas and recovery bundle

## 4. Quality

- [x] 4.1 Unit tests: device id stable, bind mismatch, burn slot, round-trip mint/unwrap
- [x] 4.2 `cargo clippy --workspace -- -D warnings` and `cargo test`
