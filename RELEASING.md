# Releasing nvlt

This repo uses GitHub Actions for **CI** (every push/PR to `main`) and **releases** (when you push a version tag).

## Day-to-day commits

Normal development — no tag needed:

```bash
git add .
git commit -m "Describe your change"
git push origin main
```

After push, check **Actions → CI** on GitHub. It runs `cargo test` and `clippy` on Linux (that already compiles the workspace; release binaries are built only when you push a tag).

## Shipping a release

### 1. Bump the version (optional but recommended)

Edit `cli/Cargo.toml` and set `version = "0.1.1"` (semver).

Commit on `main`:

```bash
git add cli/Cargo.toml
git commit -m "Bump cli version to 0.1.1"
git push origin main
```

### 2. Create and push a tag

The tag must match `v*` (e.g. `v0.1.1`) — that triggers **Release** workflow.

```bash
git tag v0.1.1
git push origin v0.1.1
```

Or in one step after the version commit:

```bash
git tag -a v0.1.1 -m "v0.1.1"
git push origin v0.1.1
```

**Tip:** Keep the tag aligned with `cli/Cargo.toml` `version` (`v0.1.1` ↔ `0.1.1`).

### 3. Download binaries

Open **GitHub → Releases** for the repo. The workflow uploads:

- `nvlt-<tag>-linux-x86_64.tar.gz` (+ `.sha256`)

Extract and install:

```bash
tar xzf nvlt-v0.1.1-linux-x86_64.tar.gz
chmod +x nvlt
sudo mv nvlt /usr/local/bin/   # or any dir on your PATH
nvlt --version
```

### 4. Using `gh` instead of git for the release

If you use the GitHub CLI and CI is already green:

```bash
gh release create v0.1.1 --title "v0.1.1" --notes "Short release notes"
# Prefer letting the Release workflow create assets; push the tag only:
git push origin v0.1.1
```

Do **not** create a release manually with empty assets if you rely on the workflow — push the **tag** and let Actions attach the tarballs.

## Workflows

| File | Trigger | What it does |
|------|---------|----------------|
| `.github/workflows/ci.yml` | Push/PR to `main` | Tests + clippy on Linux |
| `.github/workflows/release.yml` | Push tag `v*` | Linux x86_64 binary + GitHub Release |

## Troubleshooting

- **Release did not run:** Tag must be `v0.1.0` style, not `0.1.0` only.
- **CI fails on Rust version:** Workspace requires Rust **1.98+** (`rust-version` in root `Cargo.toml`).
- **Other platforms:** Release artifacts are Linux x86_64 only for now. On macOS or ARM Linux, use `cargo install --git … -p cli` from the tag.
