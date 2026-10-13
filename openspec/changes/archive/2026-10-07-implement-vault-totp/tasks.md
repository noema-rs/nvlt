## 1. Crate setup

- [x] 1.1 Add `totp/` member (package name `totp`, lib name `vault_totp` if needed to avoid conflicts)
- [x] 1.2 JSON v1 entry types

## 2. Store API

- [x] 2.1 load/save encrypted `totp.age`
- [x] 2.2 add, list, get (code + TTL), remove with validation

## 3. QR

- [x] 3.1 export/import otpauth URI (file-based minimum; QR image optional follow-up)

## 4. Tests

- [x] 4.1 CRUD round-trip with valid base32 secret
