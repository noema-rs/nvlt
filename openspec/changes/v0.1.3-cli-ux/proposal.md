# Proposal: v0.1.3 CLI UX

Delivers GitHub issues #1–#6: SSH activate naming, files/env ergonomics, snapshot identity separation, interactive path prompts, and TOTP multi-account keys.

## Scope

- SSH activate uses registered key basename under `~/.ssh`
- Files encrypt/decrypt prompts for vault name and output path
- Env edit and dotenv import
- Snapshot bundle (`user.age` / `user.pub`) separate from sync identity key path; interactive prompts
- Age and snapshot commands prompt for sensitive paths when omitted
- TOTP CRUD keyed by `(site, account)`

## Non-goals

- `snapshot sync` merge workflow
- Automatic migration renaming `host.age` in existing git repos (use `sync.host_file` config or re-export)
