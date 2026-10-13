## 1. OpenSpec

- [x] 1.1 proposal, design, delta specs, tasks

## 2. Implementation

- [x] 2.1 Extend `wipe.rs` with config reset helper
- [x] 2.2 Add `panic.rs`: confirm PANIC token, password verify, wipe, save config
- [x] 2.3 Wire `nvlt panic` in `main.rs` and lifecycle dispatch
- [x] 2.4 INIT.md / README one-paragraph panic + recovery

## 3. Quality

- [x] 3.1 Unit test: panic clears init fields (temp dir)
- [x] 3.2 `cargo clippy` and `cargo test`
