# tenant — Rust port of the macOS tenant-account CLI

A small CLI that provisions macOS user accounts, a primary share group
(`<name>-tenant-share`, UID/GID ≥600), a per-tenant TOML profile
(`~/.config/tenant/profiles/<name>.toml`), and a per-tenant PF anchor
(`/etc/pf.anchors/tenant-<name>`, referenced from `/etc/pf.conf`).
Follows Rust idioms: clap derive, composition-root DI, trait-object ports.

Verbs (full semantics live in `src/cli.rs` doc comments / `tenant --help`):

- `create <name>` — provision user + group + cowork dir + keychain + profile + PF anchor
- `destroy <name>` — convergent teardown; leaves the cowork dir intact
- `mode <name> install|runtime` — egress tier reapply (Light)
- `inbound <name> restricted|permissive` — inbound loopback reapply (Light)
- `shell <name> [--mode] [--inbound] [-d <dir>] [-- <cmd>]` — enter the tenant (Light reapply + auto-narrow)
- `reload [<name>]` — canonical "apply everything" (Full reapply); heals Light drift
- `bootstrap [<name>]` — run the merged profile's `[bootstrap]` commands as the tenant
- `doctor [<name>] [--strict]` — read-only audit
- `setup` — host-wide opt-in prep (Touch ID for sudo, SSH_AUTH_SOCK sudoers drop-in)
- `help [profile]` — long-form topic help

## Scope

This file is the always-loaded core: file map, cross-cutting doctrine, dev
loop. A shipped feature adds at most a few lines here. Everything else
lives in the code itself — names, types and tests — not in comments (see
Comments). Procedures live in `.claude/skills/` (`release`, `add-verb`),
chronology in `git log`. Reference only tracked files.

## File map

```
src/lib.rs             — run(Cli, &dyn HostUserDirectory, &dyn HostMachine, Terminal) + module tree
src/cli.rs             — clap surface; argv parsed at the binary boundary
src/terminal.rs        — Terminal: operator-I/O capability, built once at the boundary
src/ansi.rs            — per-stream color gate + rule() divider
src/domain/            — ports (host_user_directory.rs, host_machine.rs), Op ADT (ops.rs),
                         errors.rs, ids.rs newtypes
src/domain/tenants.rs  — facade: Tenants + generic narrate-execute dispatcher + load_profile +
   + tenants/            name builders; per-verb submodules own their error type + impl + helpers
src/domain/commands.rs — verb dispatch (no I/O); surface_*_error routing; upfront plan builds
src/domain/reporter.rs — operator output; owns Terminal; per-verb _intent/_summary/_done triples
src/adapters/          — macos/ prod adapters (user_directory: per-call dscl; host_machine:
                         owns ALL argv) + dry_run_host_machine.rs
src/allocation.rs      — UidAllocator + GidAllocator, independent, both floor 600
src/profile.rs         — TOML schema + PartialProfile include/merge rail + expand_tenant_path
src/firewall.rs        — pure anchor render + tenant_anchor_name/_path
src/doctor.rs          — pure grep-and-classify; all I/O in Tenants::doctor_*
src/resources/         — static operator text via include_str! (scaffold TOML, help bodies);
                         interpolated messages stay in code
src/main.rs            — composition root

tests/cli_<verb>.rs    — E2E per verb through tenant::run (bulk of coverage); cli.rs parser
                         cross-cutting; common/ builders+runners; adapters/ stubs
tests/macos_host_machine.rs, intent_labels.rs — per-variant argv + label pins
tests/doctor.rs, *_parse.rs — combinatorial pure-fn coverage
```

## Doctrine

Cross-cutting rules a cold reader could plausibly violate. They live here
only — code comments don't restate or cite them.

### Shape

- **Intent / mechanism split.** Op ADTs express *what*; `MacosHostMachine`
  owns argv — Tenants never builds argv. Tests assert op identity; literal
  shell shape is pinned in `tests/macos_host_machine.rs`.
- **One `HostMachine` trait.** A new sub-domain is a `describe_*`/
  `execute_*` method pair + a leaf `Op<'_>` variant — never a new trait.
  New method fits `Result<(), E>` → ADT variant; non-unit return (exit
  code, content, probe verdict) → carve-out method called directly.
- **Doctor probes are carve-outs, not `Op` variants** — how doctor LEARNS,
  not what a verb DOES.
- **Probe via HostMachine, not HostUserDirectory re-read.**
  HostUserDirectory is up-front inventory; mid-execution follow-ups are
  HostMachine calls. Host-owned paths probe host-side (`host_path_kind`);
  tenant-perspective paths probe via sudo (`tenant_path_kind`) — the
  tenant-side probe breaks when the tenant user is absent.
- **Reuse `HostFileError`** across host-config substrates (sudoers, pam.d,
  on-disk anchor); its Display names the path.

### Layering + DI

- **No I/O in command logic.** `commands::dispatch` and `Tenants` call
  Reporter's verb-named methods; neither touches raw writers nor checks
  `cli.verbose`/`cli.dry_run` — that branching lives in Reporter.
- **Composition-root DI.** Prod impls in `main.rs`; tests build stubs and
  parse via `try_parse_from`. `--dry-run` swaps in `DryRunHostMachine`.
  The test seam stays at the `HostMachine` boundary.
- **Terminal is the capability.** All operator I/O threads through
  `Terminal` as one value — never carve out `fn h(stderr: &mut dyn Write)`.
- **Adapters live under `.../adapters/`** — production in `src/`,
  test-only stubs in `tests/`.

### Stances

- **Lexical → state check order.** Charset validation before OS probes.
- **Convergent teardown.** Destroy-absent is a successful noop; orphan
  group converges. The final kernel-anchor flush is load-bearing (pfctl
  doesn't GC anchors — see `destroy.rs`); create/reapply paths do NOT flush.
- **State a macOS update resets is a convergence target.** Updates rewrite
  `/etc/pf.conf` (anchor references), user records (`PrimaryGroupID`) and
  `/etc/sudoers`. Every reapply re-asserts what it can; doctor reports the
  rest as Critical; nothing written at `create` is assumed to persist.
- **The tenant keychain is `tenant.keychain-db`, never `login.keychain-db`**
  (`TENANT_KEYCHAIN_FILE`) — macOS 26.6+ refuses the login name outside
  the user's session.
- **Centralized name builders** (`tenant_share_group_name`,
  `firewall::tenant_anchor_name`/`_path`, `cowork_dir_path`) — don't
  inline `format!`.
- **UID/GID allocators are independent** and may diverge; don't fuse.
- **Two anchor axes, no state file.** Egress tier and inbound posture
  resolve independently; every reapply renders both, the uncontrolled axis
  to steady state. Widenings never compose across commands
  (implicit-current-mode doctrine). `restricted` is surface-reduction, NOT
  host-vs-peer isolation — pf can't see the initiator on shared loopback.
  `[inbound]` gates only tenant-opened listeners; tenant→host loopback
  always passes.
  Inbound steady state is the profile's `posture`; an explicit
  `restricted` on a permissive profile refuses (64) — edit the profile.
- **`ReapplyScope::{Light, Full}` splits reapply by cost.** Light
  (mode/shell) skips the recursive ACL + cowork passes — inheritable ACE
  bits make that sound in steady state; Full (reload,
  create-post-provision) runs them. Light-skipped drift surfaces via
  doctor; remediation is `tenant reload`.
- **Auto-narrow protects only the `tenant shell` entry path** — `sudo -iu`
  bypasses the binary; shell is the canonical entry.
- **Bootstrap is a verb, not a reload pass.** Reload reapplies
  *descriptions of state* (inherently safe); `[bootstrap]` commands are
  *actions* — re-running them is operator-chosen.
- **Pre-exec doctor summary is a courtesy, never an abort gate** — except
  `shell` on a critical finding: a default-no `[y/N]` (`-y` allows).
- **Exit codes.** `0` success (incl. convergent noops, default doctor);
  `64` (`EX_USAGE`) user-input refusal; `74` (`EX_IOERR`) substrate
  failure on every verb except shell — shell propagates the child's exit
  (clamped 0..=255; narrow-on-finally failure warns without overriding);
  `1` clap parse default; doctor `--strict` maps `1` warning / `2`
  critical. Doctor finishes the whole walk past a failed probe, then
  exits `74`.

### Conventions

- **Acronyms are words**: `Uid`, `Macos` (identifiers keep `uid`/`gid`/
  `host`).
- **Newtypes (`ids.rs`) are tags, not validity proofs** — validation at
  dispatch. Pure string formatters take `&str`; the type-safety win is at
  the boundaries and ADT variants.
- **`-v`/`--dry-run`/`-y` are clap-global**; per-verb flags stay scoped.

### Comments

- **Default is no comment.** Knowledge lives in the code: a name that
  says the difference, a type that forbids the bad state, a test that pins
  the behavior. Comment only a trap the code can't express — external
  behavior (sudo, dscl, pfctl, PAM, `security`), a security reason,
  load-bearing ordering — in 1–3 lines at that site. In a test, that
  comment is one line naming the trap a non-obvious pin guards.
- **Doctrine here, mechanism there.** A bullet in this file may point
  into the code (`see destroy.rs`); the site comment then carries the
  external fact (pfctl doesn't GC anchors), never the rule.
- **Never:** restating the code or a test's name/assertions; a test
  re-explaining production mechanics; restating doctrine from this file;
  history ("legacy", "previously", "today's shape", cycle refs);
  bookkeeping ("pub for the pin in …", "single source so X can't drift");
  multi-line section banners; `//!` headers restating the file map.
- **Prose that explains a name is a smell.** Rename or restructure; if
  that's out of scope, leave one line `// TODO(smell): …` — one marker
  per smell, at the site you'd edit. A defect is not a smell: fix it or
  file an issue. Harvest with `rg 'TODO\(smell\)'`.
- **Exempt:** `src/cli.rs` doc comments — they are `--help`.

## Test discipline

E2E-first. Bulk in `tests/cli_<verb>.rs` through `tenant::run` with
`StubUserDirectory` + `StubHostMachine`; shared helpers in
`tests/common/mod.rs`. Inline `#[cfg(test)] mod tests` is out of style;
standalone unit files are only for substrate-boundary pins and
combinatorial pure-fn coverage. `run_with` wires `NeverHostMachine`
(panics on any substrate call); `run_with_exec` lets the test own the
machine. Behavioral assertions = op identity; display assertions =
byte-exact (cosmetic tweaks need test edits).

## Local dev

```
just check   # fmt + clippy -D warnings + test (pre-merge gate)
just fmt     # in-place format
just test    # cargo test
just run create somename --dry-run -v   # invoke the binary; args after `run` forward
just build   # release binary
just install # cargo install --path . (puts `tenant` on PATH via ~/.cargo/bin)
```

Pre-commit hooks run `cargo fmt --check` + `cargo clippy --all-targets -- -D
warnings` on `.rs` commits (local-only; `pre-commit install` once after
clone).

Releases: see the `release` skill (`.claude/skills/release/`).
