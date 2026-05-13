# tenant — Rust port of the macOS tenant-account CLI

A small CLI for provisioning macOS user accounts, primary groups (named
`<name>-tenant-share`) in a project-reserved UID/GID range (≥600), a
per-tenant profile (TOML at `~/.config/tenant/profiles/<name>.toml`),
and a per-tenant PF anchor (`/etc/pf.anchors/tenant-<name>` referenced
from `/etc/pf.conf` and loaded via `pfctl -f`). `tenant create <name>`
inspects host account state, validates input, picks the next free UID
and GID independently, and either renders the planned shell invocations
(`--dry-run`) or executes them (real mode). `tenant destroy <name>` is
the symmetric teardown verb that runs `sysadminctl -deleteUser`, a dscl
residue probe + conditional cleanup, `dseditgroup -o delete`, profile
removal, the PF teardown (backup → remove anchor → update pf.conf →
reload), and a final `pfctl -a tenant-<name> -F all` to flush the
anchor's in-kernel rules. `tenant mode <name> install|runtime` re-renders
the per-tenant PF anchor with the requested allowlist tier (`runtime`
only, or `runtime + install`) and reloads pf — used to widen the tenant's
egress allowlist for install-tier work and narrow back when done.
`tenant shell <name>` auto-narrows back to runtime tier before launching
the login shell, so any leftover install-tier widening becomes truly
session-scoped — the next shell entry resets the allowlist.

This crate is a Rust port of an earlier Go prototype (lives at
`/Users/plugin-dev/src/tenant/` for cross-reference). The Rust version
does not mirror the Go shape literally; it follows Rust idioms (clap derive,
composition-root DI, trait-object Reader, etc.) and has diverged where the
two languages' conventions diverge.

## Scope

This file carries the stable doctrine and the file map below — facts
that describe what the code *currently does*, not what we plan to do
next. For the chronology of shipped versions, `git log --oneline`
walks the commits.

## File map

```
src/lib.rs        — public API (`run`); `Cli` + `Verb` + `ModeLevel`; mode swap to `DryRunExecutor` when `--dry-run`; constructs Reporter with the active Executor.
src/commands.rs   — verb dispatch (the `match` on `Verb`). No I/O, no mode/verbosity branching; routes to Reporter methods.
src/accounts.rs   — `Reader` trait + Macos/Stub impls; `Writer` (`create_tenant`, `destroy_tenant`, `destroy_orphan_group`, `shell_into_tenant`, `apply_tenant_mode`); shared private `reapply_anchor_for_level` helper drives both `apply_tenant_mode` and the shell's auto-narrow; `validate_name` / `check_conflict` / `destroy_eligibility`; `tenant_share_group_name`. `Writer::run<O: WritableOp>` couples per-step echo + execute.
src/allocation.rs — `UidAllocator` + `GidAllocator`. Independent; both iterate from `TENANT_UID_FLOOR = 600`.
src/executor.rs   — `Op` ADT root wrapping `AccountOp` / `ProfileOp` / `FirewallOp` leaves; `WritableOp` trait bridging leaves to typed execution; `Executor` trait (per-domain `describe_*` / `execute_*` pairs + `login` / `read_profile` / `read_pf_conf` non-unit carve-outs); `MacosExecutor` / `StubExecutor` / `DryRunExecutor` impls; `AccountError` / `ProfileError` / `FirewallError` types.
src/profile.rs    — `Profile` / `Allowlist` / `Tier` serde shapes; `parse` (schema-version-checked); `default_profile_toml`; `display_path_for` (`~`-rendered form used in plan / echo / error frames).
src/firewall.rs   — pure functions for PF anchor + `/etc/pf.conf` line ops: `render_anchor`, `ensure_anchor_ref`, `remove_anchor_ref`, `is_anchor_referenced`; `tenant_anchor_name` / `_path` centralizers; `ANCHOR_DIR` / `PF_CONF` / `PF_CONF_BACKUP` constants.
src/reporter.rs   — operator-facing output. Per-verb `_starting` / `_done` methods bake in phrasing and internally branch on (dry_run, verbose); `refuse_*` and `*_failed` methods to stderr; `step(op)` echoes per substrate call in real+verbose; plan rendering flows through `Op::describe_via`.
src/main.rs       — composition root: prod impls + `tenant::run`.

tests/cli.rs             — E2E tests. Helpers `run_with` (NeverExecutor — panics on substrate use, guards "should not touch the host" paths) and `run_with_exec` (caller-owned StubExecutor for real-mode assertions). Behavioral assertions on op identity; display assertions byte-exact.
tests/macos_executor.rs  — per-variant pins of the `MacosExecutor::describe_*` argv contract. One test per Account/Profile/Firewall variant so a future tool swap (dseditgroup → dscl . -create; pfctl → some future PF manager) touches one place per op.
tests/profile_parse.rs   — combinatorial coverage on `profile::parse`.
tests/firewall_render.rs — combinatorial coverage on `firewall::render_anchor`.
tests/firewall_conf.rs   — combinatorial coverage on `ensure_anchor_ref` / `remove_anchor_ref` / `is_anchor_referenced`.
```

## Project doctrine

Things that are easy to violate and would matter:

- **Intent / mechanism split** — domain ops (`AccountOp` / `ProfileOp` /
  `FirewallOp`) express *what* the verb is doing; `MacosExecutor` owns
  argv and the rendered shell-command strings (used by both the upfront
  plan block and the per-step `$` echo). The Writer never constructs
  argv; tests assert on op identity (`exec.account_ops()[N] ==
  AccountOp::CreateShareGroup{..}`), and the literal shell-command
  shape is pinned narrowly in `tests/macos_executor.rs` — one test per
  variant, so a future tool swap moves one place per op. Operator-
  facing output is also split two-tier: each verb has a `_starting` /
  `_done` pair on `Reporter` that internally branches on (dry_run,
  verbose). Plans are `&[(Op<'_>, Option<&'static str>)]` — the
  annotation slot carries `# on rollback` / `# on reload failure`.
  Conditional steps appear in the upfront plan unconditionally and
  echo via `Reporter::step` only when they actually run — the
  plan-vs-echo asymmetry is the operator-visible signal that a
  conditional step was skipped. Interactive verbs (`shell`) use a
  `_starting`-only pair (no `_done`) because the operator becomes the
  shell after `login` returns.

- **One Executor trait; sub-domains live as method-pairs** — `Op<'a>`
  wraps `&AccountOp` / `&ProfileOp` / `&FirewallOp`. Display goes
  through `Op::describe_via(executor)` — uniform across domains.
  Execution goes the other direction via `WritableOp::execute_via`,
  preserving per-domain error types (`AccountError`, `ProfileError`,
  `FirewallError`) so `CreateError::Group(AccountError)` /
  `Profile(ProfileError)` / `Firewall(FirewallError)` stay typed
  end-to-end. Adding a future sub-domain (sudoers, keychain) extends
  the existing `Executor` with a new `describe_*` / `execute_*` pair
  and adds a leaf variant — no new trait. The single `Executor` is
  the one test seam at the host boundary.

- **Carve-out methods for non-unit returns** — three Executor methods
  don't fit the `Result<(), E>` shape and are called directly by the
  Writer rather than routed through `WritableOp`: `login(name) ->
  Result<i32, AccountError>` (interactive — inherits stdio so sudo
  can prompt; returns child exit code), `read_profile(name) ->
  Result<String, ProfileError>`, `read_pf_conf() ->
  Result<String, FirewallError>`. The `LoginAsUser` variant exists
  in `AccountOp` only for plan/echo rendering via `Op::describe_via`
  — it's intentionally NOT a `WritableOp` impl. When adding a future
  executor method, ask "does the return fit `Result<(), E>`?" — if
  yes, ADT variant; if no, carve-out.

- **Interactive verbs use `login`, not `execute_account`** —
  `execute_account` captures stdout/stderr (suppresses sysadminctl
  chatter on success, surfaces it via `AccountError::NonZero` on
  failure — right for batch verbs); `login` inherits the parent's
  stdio so sudo can prompt and the launched login shell can drive
  the controlling terminal. Wiring `shell` through `execute_account`
  would silently swallow the shell session's output. `AccountError`
  is reserved for `login` *spawn* failures only; child exit codes
  propagate via the i32 return.

- **Probe via Executor, not Reader live re-read** — when a verb
  needs to re-check OS state mid-execution (destroy's
  `LookupUserRecord` residue probe is canonical), the probe is a
  regular substrate call whose `Ok(())` vs
  `Err(AccountError::NonZero{..})` drives a branch in the Writer.
  The Reader trait stays snapshot-then-act — it's the in-memory
  view captured at composition-root time. Don't add a "live re-read"
  method to Reader.

- **No I/O in command logic** — `commands::dispatch` and
  `accounts::Writer` both call Reporter's verb-named methods
  (`refuse_*`, `create_*_failed`, `destroy_*_failed`, `shell_failed`,
  `mode_*_failed`, `destroy_absent`, `_starting`, `_done`, `step`).
  Neither touches raw writers nor checks `cli.verbose` /
  `cli.dry_run` — mode/verbosity branching lives inside Reporter.

- **Lexical → state-based check order** — `validate_name` (charset)
  runs before `check_conflict` / `destroy_eligibility` (OS state)
  in dispatch. Cheaper failure first.

- **Convergent semantics for teardown verbs** — `destroy <name>`
  against an absent tenant is a successful noop, not an error
  (`reporter.destroy_absent` + exit 0). When the user is absent but
  a stale `<name>-tenant-share` group remains (orphan-group state
  from a failed prior destroy), `destroy_eligibility` returns
  `OrphanGroup` and dispatch routes to `Writer::destroy_orphan_group`
  to converge. The orphan path runs the full PF teardown too (each
  PF step is idempotent), so partial-firewall state from a failed
  earlier create gets converged as well. Same convergent contract
  applies to future teardown verbs.

- **`<name>-tenant-share` and `tenant-<name>` are centralized** —
  `accounts::tenant_share_group_name(name)` is the single source of
  truth for the group suffix; `firewall::tenant_anchor_name(name)`
  for the anchor prefix. Don't inline `format!("{name}-tenant-share")`
  or `format!("tenant-{name}")` at call sites — the centralization
  lets a future suffix/prefix change happen with one edit.

- **Decoupled UID/GID allocation** — `UidAllocator` reads `used_uids`,
  `GidAllocator` reads `used_gids`; the two spaces are disjoint and
  may legitimately diverge (UID 613, GID 600 on a host with prior
  tenants). Don't fuse them. The
  `verbose_uid_and_gid_allocators_cross_over` test pins divergence
  with a crossover stub — strongest defense against a regression
  that wires `dseditgroup -i <gid>` to `lowest_free_uid`.

- **Create partial-failure rollback / recovery posture** —
  `Writer::create_tenant` returns `CreateError::{Group, User,
  UserWithRollback, Profile, Firewall}`. `UserWithRollback` emits
  two Reporter calls (the original error frame plus an em-dash-
  suffixed rollback-failed hint). Profile/Firewall failures leave
  the user + group (and any partial PF state) on the host;
  recovery is `tenant destroy <name>` — destroy is idempotent on
  PF, so partial anchor state converges. On PF Reload failure
  specifically, the Writer runs an automatic 4-step recovery
  (RestoreConfigFromBackup → RemoveAnchor → Reload → FlushAnchor)
  BEFORE surfacing the error; recovery-of-recovery (restore itself
  fails) surfaces as `FirewallError::RestoreFailed { path }` and
  renders with a manual-recovery hint naming the backup path and
  the `sudo cp` command.

- **PF anchor flush is load-bearing on destroy paths** — `pfctl -f
  /etc/pf.conf` reloads the parent ruleset but does NOT garbage-
  collect anchors whose `load anchor` directive has been removed.
  Without an explicit `pfctl -a tenant-<name> -F all`, the previous
  tenant's rules persist in kernel memory under an orphan anchor
  name and the next tenant getting the same UID silently inherits
  them. `FirewallOp::FlushAnchor` is the final step on both destroy
  paths (`destroy_tenant`, `destroy_orphan_group`) and on the
  create-side reload-failure recovery. Tests pin "FlushAnchor is
  the last firewall op on both destroy paths" AND "create's success
  path does NOT invoke FlushAnchor" (negative pin against wiring
  that would wipe rules we just installed). The load-bearing-ness
  is specific to the "parent directive removed" case; a defensive-
  flush habit would blur the principle.

- **Mode-reapply is `InstallAnchor → Reload` with no flush and no
  recovery** — `tenant mode <name> {install|runtime}` re-renders
  the anchor body and reloads pf. The parent `load anchor`
  directive stays in place across mode reapply, so `pfctl -f`
  re-reads the anchor file and replaces the in-kernel ruleset on
  every reload — no orphan-anchor case, no `FlushAnchor` needed.
  Verified empirically by manual smoke testing (kernel `<allowed>`
  table shrinks back to runtime-tier size on narrow); if that ever
  flips, the fix is one line — insert `FlushAnchor` before
  `InstallAnchor` in `Writer::apply_tenant_mode`.
  On Reload failure, mode does NOT attempt a
  `RestoreConfigFromBackup`-style recovery — the operator reruns
  the verb (idempotent at the substrate). Negative pin in tests:
  mode flow records exactly `[InstallAnchor, Reload]` — no
  `FlushAnchor` / `BackupConfig` / `RestoreConfigFromBackup` /
  `RemoveAnchor` / `UpdateConfig` / `Enable`.

- **Shell auto-narrows on entry, unconditionally, abort-on-failure**
  — every `tenant shell <name>` reapplies the runtime-tier anchor
  body via the shared `reapply_anchor_for_level(name,
  ModeLevel::Runtime, reporter)` helper BEFORE handing off to
  `Executor::login`. The narrow is unconditional (no "are we
  already in runtime?" check) — same structural reasoning as Q2's
  "on-disk anchor is the source of truth" lock; reapply is
  idempotent at the substrate. The narrow is also load-bearing: if
  it fails, the login is NOT launched. New `ShellError { Account,
  Mode }` carries the abort posture through to `commands::dispatch`,
  which routes Mode failures through `Reporter::shell_narrow_failed`
  (firewall) and `Reporter::shell_narrow_profile_failed` (profile
  read/parse). Both methods frame the failure as "before shell
  entry" so the operator sees verb context, not mode-verb framing.
  Operator recovery: `tenant mode <name> runtime` to narrow
  manually, then retry `tenant shell <name>`. Cycle 4's shell plan
  grows from 1 op (`LoginAsUser`) to 3 (`InstallAnchor` + `Reload`
  + `LoginAsUser`); `shell_starting` takes a `plan` slice matching
  create/destroy/mode's signature. Same no-defensive-flush /
  no-auto-recovery posture as the mode verb (the helper is shared);
  negative pin in tests confirms no `FlushAnchor` / `BackupConfig`
  / `RestoreConfigFromBackup` / `RemoveAnchor` ever fires on the
  shell path.

- **Auto-narrow only protects the `tenant shell` entry path** —
  an operator who runs `sudo -iu tenant` directly bypasses the
  tenant binary and inherits whatever PF posture the anchor file
  currently holds. If install-tier widening was left in place
  before a reboot, pf.conf reloads the (still-widened) anchor on
  boot and a direct `sudo -iu` enters under the widened posture.
  `tenant shell <name>` is the canonical entry point; document
  this limitation rather than mitigate it (would require either
  always-render-runtime on every reboot, or a separate watcher
  process — out of scope for cycle 4).

- **Tenant-floor guard on destroy** — `destroy_eligibility` refuses
  with `EX_USAGE 64` when the named account exists with a UID
  below `TENANT_UID_FLOOR` (`NotATenant`) or with no positive UID
  at all (`SystemAccount` — `nobody` and other negative-UID
  service accounts). Charset rail (`validate_name`) is the
  upstream guard; the floor is the downstream guard. Both are
  hard rails today; making them config-overridable with `--force`
  is on the roadmap.

- **Snapshot-then-act on the Reader** — `MacosReader::new()`
  queries dscl once at composition-root construction; every
  subsequent lookup is served from that in-memory snapshot. A
  concurrent admin process mutating `/Users` between snapshot and
  `sudo sysadminctl …` could in principle cause us to destroy an
  account whose UID changed after we cleared it. Exploitation
  requires concurrent root (the attacker could already destroy any
  account directly), so we accept the TOCTOU window today. If a
  future use case widens exposure (e.g. long-running daemon mode),
  the mitigation is to pass `-UID <verified>` to sysadminctl to
  bind the call to the UID the guard cleared.

- **Composition-root DI** — `tenant::run` takes `&dyn
  accounts::Reader` and `&dyn executor::Executor`. `main.rs`
  builds prod impls (`MacosReader`, `MacosExecutor`); tests build
  their own (`StubReader`, `StubExecutor` / `NeverExecutor`).
  Writer and Reporter are constructed inside `run` from the active
  Executor — both swap to `DryRunExecutor` when `cli.dry_run` so
  the dry-run path renders plan + echo lines lazily via
  `Op::describe_via`. The test seam stays at the Executor boundary.

- **Exit codes** — `0` success (including destroy's convergent noop
  and the orphan-group convergence path); `64` (`EX_USAGE`,
  sysexits.h) for user-input failure — validation, create-side
  conflict, all refusals (destroy / shell / mode);
  `74` (`EX_IOERR`) for substrate execution failure on every verb
  except shell. Shell is the exception on its success path: when
  `login` returns Ok, the child shell's exit code propagates as
  tenant's own exit (clamped 0..=255). `1` is clap's default for
  parse errors and `ModeLevel` rejection.

- **Acronym casing** — Rust convention treats acronyms as words:
  `Uid` not `UID`, `Macos` not `MacOS`. Methods are
  `lowest_free_uid`, struct is `UidAllocator`, `MacosReader`.

- **Clap flag scoping** — `-v / --verbose` and `--dry-run` are both
  `global = true` on `Cli` (accept either before or after the
  subcommand). Per-subcommand flags (e.g. `--strict`, `--json`,
  `--yes`) stay scoped to their verb.

## Test discipline

E2E-first. The bulk of tests live in `tests/cli.rs` and drive through
`tenant::run` with a `StubReader`. Inline `#[cfg(test)] mod tests`
blocks are out of style on this project; standalone unit-test files
need explicit justification — `tests/macos_executor.rs` is the
canonical precedent (per-variant `describe_*` pins for the argv
contract). `tests/profile_parse.rs`, `tests/firewall_render.rs`, and
`tests/firewall_conf.rs` each carry the same justification:
combinatorial coverage on a pure function (`parse`, `render_anchor`,
`ensure_anchor_ref` / `remove_anchor_ref` / `is_anchor_referenced`)
whose call sites are inside the writer and would otherwise need many
overlapping E2E tests. Per-variant or per-shape unit testing is the
right tool when the function's state space is combinatorial; CLI E2E
remains the default for verb-level behavior.

Two helpers in cli.rs: `run_with(stub, args) -> (u8, String, String)`
wires a `NeverExecutor` (panics if any substrate method is called —
guards "should not touch the host" paths like dry-run / validation /
conflict). `run_with_exec(stub, &StubExecutor, args)` lets the test
own the executor for real-mode assertions on op shape / configured
failure. Both run the binary in-process and return exit code + stdout
+ stderr as `String`s.

Behavioral assertions are on op identity (`exec.account_ops()` returns
`Vec<AccountOp>`; same for `profile_ops()` / `firewall_ops()`;
`exec.logins()` returns `Vec<String>`). Display assertions are
byte-exact on rendered output. They pin the user-facing contract;
cosmetic message tweaks need test edits.

## Local dev

```
just check        # fmt + clippy -D warnings + test (pre-merge gate)
just fmt          # in-place format
just test         # cargo test
just run create somename --dry-run -v   # invoke the binary; args after `run` forward
just build        # release binary at target/release/tenant
just install      # cargo install --path . (puts `tenant` on PATH via ~/.cargo/bin)
```

Pre-commit hooks run `cargo fmt --check` (via `just check-fmt`) and
`cargo clippy --all-targets -- -D warnings` on commits touching `.rs`.
They're local-only (`language: system`), no PyPI / GitHub deps. Run
`pre-commit install` once after a fresh clone if the hook isn't wired.
