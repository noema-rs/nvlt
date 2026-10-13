## 1. Crate setup

- [x] 1.1 Add `passwords/` member with `Cargo.toml`, README, `#![forbid(unsafe_code)]`
- [x] 1.2 Define serde types for v2 schema (entries, totp block, fields)

## 2. Store API

- [x] 2.1 Load/decrypt and encrypt/save `pass.age` through `vault_core`
- [x] 2.2 CRUD: list, search by domain, get, add, edit, remove with duplicate checks
- [x] 2.3 Export confirmation message structs for edit/remove (English strings)

## 3. Tests

- [x] 3.1 Round-trip save/load with test key
- [x] 3.2 Duplicate and not-found errors
