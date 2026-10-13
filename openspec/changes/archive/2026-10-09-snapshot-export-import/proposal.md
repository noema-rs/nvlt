# Proposal: snapshot export / import

Rename the public git bundle workflow from `sync push` / `sync pull` to **`snapshot export`** and **`snapshot import`**, reflecting full-snapshot transfer rather than bidirectional sync. Reserve **`snapshot sync`** (future) for manifest diff and merge.

## Scope

- CLI: `nvlt snapshot export --path <dir>`, `nvlt snapshot import --path <dir>`
- Remove `nvlt sync push` / `sync pull` (breaking CLI rename; no compatibility alias unless requested later)
- Update vault-sync, vault-cli, vault-lifecycle, vault-config spec wording
- Docs: README, INIT.md, cli/README.md
- Config TOML `[sync]` section unchanged (host artifact names)

## Non-goals

- `snapshot sync` implementation
- Renaming `[sync]` config keys or `vault-sync` capability id
