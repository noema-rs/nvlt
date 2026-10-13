## Context

See `proposal.md`. Today `nvlt.enc` wraps TOTP seeds with password-only JSON; unlock loads it directly. No device bind or attempt budget exists.

## Goals / Non-Goals

**Goals:**

- Fifteen RT/enc duplas; burn RT on any auth failure after slot selection; success preserves slot.
- Ed25519-signed RT payloads; bind stored in paired `.enc` AAD (dev, ino, size, content hash at mint).
- Linux `device_id` in config; mismatch triggers wipe of vault root operational files.
- Offline recovery bundle (age-encrypted) with seeds + rate-limit private key; `rate-limit renew` remints duplas.
- Integrate with existing `derive_key(password, seed, lock salt)` for vault `.age` files.

**Non-Goals:**

- TPM, rebind command, legacy `nvlt.enc` auto-migration (document renew / from-snapshot).

## Decisions

1. **Crypto crate**: `ed25519-dalek` with `rand` for keygen; RT signature over canonical CBOR/msgpack of `{version, slot, generation, device_id, key_seed}`.
2. **Slot enc format**: age encrypt (existing `vault_core::encrypt`) of JSON seed blob (same structure as current `NvltEncFile` inner wraps) with key `HKDF(password, rt.key_seed, slot, generation)`; AAD = bind blob `{dev, ino, size, blake3(content_rt)}`.
3. **Burn RT**: append random byte to `.rt` file (invalidates bind hash and signature verification if we include file hash in bind — bind uses RT file hash at mint, so mutation breaks match). Alternative: truncate; we use append 1 byte for simplicity.
4. **Slot selection**: scan `01..15`, first where RT verifies and bind matches live stat/hash.
5. **Recovery bundle**: `recovery.age` written to user-specified path at init; plaintext payload JSON `{device_id, primary, backup, rate_limit_secret_key}` encrypted with key from user recovery passphrase (Argon2). Not stored in vault root.
6. **Wipe**: remove `pass.age`, `totp.age`, `backup.age`, `envs/`, `files/`, `rate/`, legacy `nvlt.enc`, `ssh.age` if present; clear agent session; optionally reset config lock fields (keep bootstrap path) — spec says wipe operational content; we remove encrypted stores + rate + nvlt.enc, leave config.toml with message or remove device_id to force re-init.

   Simpler wipe: delete known layout paths from `VaultLayout` except config.toml; set rate_generation 0 and clear device to force re-init message.

7. **Constants**: `RATE_SLOT_COUNT = 15`.

## Risks / Trade-offs

- [Root rollback of rate/] → Accepted; document threat model.
- [VM clone same machine-id] → Accepted; note in INIT.
- [Inode reuse after delete] → New mint on renew creates new files; old binds invalid.
- [Failed unlock modified scenario] → Only rate artifacts change on burn, not pass.age.

## Migration Plan

- Detect legacy `nvlt.enc` without `rate/` → `status` warns; unlock errors with hint to run `rate-limit renew` after manual bundle creation OR re-init from snapshot.
- For dev/testing: fresh init creates new layout.

## Open Questions

- None blocking v1.
