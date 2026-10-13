## Context

See `proposal.md`. `wipe_operational_vault` already exists for device fingerprint mismatch; panic is user-initiated with stronger UX.

## Goals / Non-Goals

**Goals:**

- One command to remove local ciphertext, `rate/`, legacy `nvlt.enc`, and agent session.
- Clear `lock`, `device_id`, `rate_limit_pub`, `rate_generation` from `{vault}/config.toml` so status shows uninitialized while keeping `vault.path` and KDF settings.
- Confirmation requiring typed `PANIC` plus default-deny yes/no prompt.
- Require master password when vault is initialized (proves intent; blocks casual DoS by another user without password).

**Non-Goals:**

- Wiping bootstrap `~/.config/nvlt/config.toml` by default.
- Deleting snapshot directory outside vault root.

## Decisions

1. **Shared wipe function** in `wipe.rs`: `wipe_operational_vault` + new `clear_vault_init_config(config)` saved after wipe.
2. **Password check**: derive attempt against `pass.age` before wipe if `pass.age` exists; if not initialized, skip password.
3. **Silent output**: print short English message with recovery hint (`init --from-snapshot`), no secrets.
4. **No rate-limit burn**: delete entire `rate/` directory.

## Risks / Trade-offs

- [Attacker with password triggers panic] → DoS local; user restores from snapshot — acceptable per product stance.
- [User panics by mistake] → mitigated by typed `PANIC` + password + confirm.

## Migration Plan

None; new command only.
