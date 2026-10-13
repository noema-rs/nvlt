## Goals / Non-Goals

**Goals:** JSON v1 `totp.age` blob; site-keyed entries; generate codes via core.

**Non-Goals:** Password-embedded TOTP (passwords crate).

## Decisions

- Enforce RFC6238 minimum secret length (≥128 bits decoded) on add/import — align INIT examples with generated seeds at init.
- QR import/export: use `totp-rs` otpauth + optional qrcode crate when implementing.

## Risks / Trade-offs

- INIT example seed `JBSWY3DPEHPK3PXP` is too short for `totp-rs` 5.x — init must generate proper secrets.
