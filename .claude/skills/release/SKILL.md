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

1. Claude: edit `RELEASE_NOTES.md` (leaving it uncommitted is fine —
   prepare commits it).
2. Operator, from the host: `just release-host X.Y.Z <NEXT>` — one shot:
   pushes main, runs `release-prepare` (all its guards), `release-publish`,
   polls until the Action publishes the tarball, bumps the Homebrew tap
   (`url` + `sha256` in `Formula/tenant.rb`, commit `tenant X.Y.Z`, push),
   then `release-bump-dev <NEXT>`.

The individual recipes (`release-prepare` / `release-publish` /
`release-bump-dev`) remain for stepwise runs or recovery; abort a prepared
but unpublished release with `git reset --hard HEAD~1 && git tag -d vX.Y.Z`.

The tap bump matters: the tap repo is NOT automated by
`.github/workflows/release.yml`, and an unbumped tap silently keeps serving
the previous version to `brew upgrade tenant`. The clone is the sibling
`../homebrew-tenant` (also at `~/src/homebrew-tenant`); `release-host`
takes the path as an optional third argument.

Sandbox constraint: this environment cannot `git push` — `release-host` is
the operator's command; Claude prepares `RELEASE_NOTES.md` and hands off.

Operator install (pre-tap): download the release tarball, or
`cargo install --git https://github.com/MuhammadFarag/tenant`.
