## 1. Init

- [x] 1.1 Generate salt, seeds (≥128-bit), dual KDF keys, empty encrypted stores
- [x] 1.2 User warnings and seed display (English)
- [x] 1.3 Persist primary seed per `totp_seed_location`

## 2. Backup

- [x] 2.1 Decrypt all with data key; build backup JSON; encrypt with backup key
- [x] 2.2 Confirmation before overwrite

## 3. Recover

- [x] 3.1 Restore from backup; new primary seed; re-encrypt all data files
- [x] 3.2 Integration test: backup → tamper primary → recover → unlock with new seed

## 4. Rotate

- [x] 4.1 New password optional; new primary + backup seeds; re-encrypt everything

## 5. Hardening docs

- [x] 5.1 Document swap/core dump recommendations in cli README (no code)
