---
name: release
description: Release the tenant CLI — version conventions, tag/publish flow, and the manual Homebrew tap bump. Use when cutting a release, tagging a version, bumping the dev version, or asked how releases work.
---

# Releasing tenant

## Version conventions

- **Dev-suffix.** Main always carries `version = "X.Y.Z-dev"`; release commits
  are the only suffix-free ones, so `tenant --version` flags non-release
  builds.
- **Tag matches Cargo.toml by construction.** `just release-prepare X.Y.Z` is
  the only sanctioned tag path (strips `-dev`, refreshes `Cargo.lock`,
  commits, tags `vX.Y.Z`); CI re-verifies.
- **Pre-1.0 bumps.** Minor for user-visible behavior, patch for bugfix-only.
  Pre-release suffixes (`0.1.0-alpha.1`, `-rc.2`) ship tagged-but-unstable;
  the `-` in the tag drives `--prerelease`. `release-bump-dev` takes the
  X.Y.Z target only (no suffix).

## Flow

1. Edit `RELEASE_NOTES.md`.
2. `just release-prepare X.Y.Z` — refuses unless local main == origin/main,
   so push any prep commits first.
3. Inspect: `git show vX.Y.Z`.
4. `just release-publish` — pushes commit + tag; GitHub Actions builds.
5. Wait for the Action to finish.
6. `just release-bump-dev <NEXT>`.
7. **Bump the Homebrew tap** (manual — NOT automated by
   `.github/workflows/release.yml`). The tap is the sibling clone
   `../homebrew-tenant` (also at `~/src/homebrew-tenant`); it goes stale
   between releases, so `git pull --ff-only` first. Update
   `Formula/tenant.rb` (`url` + `sha256` — take the sha from
   `curl -sL <release-url>/<tarball>.sha256`, or download and hash the
   tarball). Commit message convention is bare `tenant X.Y.Z`. An unbumped
   tap silently keeps serving the previous version to `brew upgrade tenant`.

Sandbox constraint: this environment cannot `git push` — pushes (prep
commits, release-publish, the tap bump) are the operator's; prepare
everything and hand off.

Operator install (pre-tap): download the release tarball, or
`cargo install --git https://github.com/MuhammadFarag/tenant`.
