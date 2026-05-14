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
`tenant shell <name>` auto-narrows back to runtime tier AND reapplies
the profile's `[[shares]]` entries before launching the login shell, so
any leftover install-tier widening becomes truly session-scoped — the
next shell entry resets the allowlist AND restores any ACL/symlink the
operator manually clobbered. `tenant reload [<name>]` is the
config-driven "I edited the profile, apply it" verb: rewrites the PF
anchor at runtime tier and reapplies each declared share (host-side
`chmod +a` ACL grant + tenant-side symlink at the expanded
`tenant_path`). No-arg form walks every tenant on the host, continues
on per-tenant failure, exits 0 clean / 74 on any failure. `tenant
doctor [<name>]` is the read-only audit verb: it walks a curated list
of sensitive host paths and probes each AS the tenant (via `sudo -n -u
<name> /bin/test -r|x`); reads the host's `/etc/sudoers` + drop-ins
to detect SSH_AUTH_SOCK env propagation; reads `/etc/pam.d/sudo` for an
active `pam_tid.so` directive (Touch-ID-for-sudo, Info-tier);
structural-checks each tenant's kernel pf anchor against `pfctl -a
tenant-<name> -sr` for missing pass / block rules (Warning-tier
drift); reads `pfctl -si` to detect globally-disabled pf
(Critical-tier — no anchor enforces); and reads each tenant's on-disk
anchor file at `/etc/pf.anchors/tenant-<name>` to detect byte-exact
drift between the file body and the profile-derived runtime-tier
render (Warning-tier; recovery via `tenant mode <name> runtime`).
Reports findings on Allowed outcomes and the host-config drift cases,
with `--strict` mapping max severity to a non-zero exit code
(1 warning / 2 critical).

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
src/lib.rs        — public API (`run`); `Cli` + `Verb` (Create / Destroy / Shell / Mode / Doctor / Reload) + `ModeLevel`; mode swap to `DryRunExecutor` when `--dry-run`; constructs Reporter with the active Executor. `run` takes `host: &str` (operator's login name) for doctor's curated-path expansion.
src/commands.rs   — verb dispatch (the `match` on `Verb`). No I/O, no mode/verbosity branching; routes to Reporter methods. `doctor_exit_code(severity, strict)` maps doctor's outcome to 0/1/2. Helpers `surface_destroy_error` / `surface_doctor_error` / `surface_mode_error` / `surface_shell_mode_error` / `surface_reload_error` / `surface_create_post_provision_error` centralize per-error-arm Reporter routing for verbs with multi-arm error types.
src/accounts.rs   — `Reader` trait + Macos/Stub impls; `Writer` (`create_tenant`, `destroy_tenant`, `destroy_orphan_group`, `shell_into_tenant`, `apply_tenant_mode`, `reload_tenant`, `reload_all_tenants`, `doctor_tenant`, `doctor_all_tenants`); shared private `build_reapply_plan` (read profile + parse + pre-flight shares + construct PF + per-share ops) and `execute_reapply_plan` (fires the constructed ops) drive `apply_tenant_mode` / `shell_into_tenant` / `reload_tenant`; `reapply_shares_post_provision` skips PF for `create_tenant`'s post-Enable share pass; `execute_share_ops` is the per-share loop shared by both execute paths; private doctor helpers: `check_env_leak` + `check_touch_id_for_sudo` + `check_pf_status` (each host-wide, single-emit) and `probe_tenant_paths` (per-tenant; runs the curated-path probes, the pf-rule structural check on the kernel anchor, the byte-exact anchor-body comparison on the on-disk file via `check_anchor_body_drift`, and the per-share ACL + symlink drift checks via `check_share_drift`). `validate_name` / `check_conflict` / `destroy_eligibility`; `tenant_share_group_name`. `Writer::run<O: WritableOp>` couples per-step echo + execute. `ReapplyPlan { install_anchor, reload, share_ops }` + `ShareOps { grant, ensure_dir, ensure_link }` carry the pre-built op list so plan rendering and execution see the same ops. `ShareError { HostPathMissing, TenantPathOccupied }`, extended `ModeError { Profile, Firewall, Acl, Account, Probe, Share }`, and `CreateError::PostProvision(ModeError)` aggregate share-substrate failures. `ReloadAllOutcome { failed }` carries the no-arg-form aggregate. `DoctorOutcome` + `DoctorError { Probe, HostFile, Firewall }` aggregate doctor's results.
src/allocation.rs — `UidAllocator` + `GidAllocator`. Independent; both iterate from `TENANT_UID_FLOOR = 600`.
src/executor.rs   — `Op` ADT root wrapping `AccountOp` / `ProfileOp` / `FirewallOp` / `AclOp` leaves; `WritableOp` trait bridging leaves to typed execution; `Executor` trait (per-domain `describe_*` / `execute_*` pairs + non-unit carve-outs: `login` / `read_profile` / `read_pf_conf` / `probe_access_as_tenant` / `read_env_policy` / `read_kernel_pf_rules` / `read_pam_sudo` / `read_pf_status` / `read_anchor_body` / `read_host_acl` / `tenant_path_kind`); `MacosExecutor` / `StubExecutor` / `DryRunExecutor` impls; `AccountError` / `ProfileError` / `FirewallError` / `ProbeError` / `HostFileError` / `AclError` types (HostFileError covers any privileged-or-cheap host-config-file read: sudoers + drop-ins, pam.d/sudo, on-disk anchor file); `AccessMode` (Read / List) + `AccessOutcome` (Allowed / Denied / Unknown) for doctor's probe vocabulary; `PathKind` (Absent / Symlink(target: PathBuf) / Other) for `tenant_path_kind`'s pre-flight + doctor's `SymlinkDrift` target comparison; `AclMode` (Ro / Rw) is the substrate-vocab sibling of profile.rs's `ShareMode`. `AccountOp::LoginAsUser` / `EnsureDirAsUser` / `EnsureSymlinkAsUser` substrate-group the `sudo -n -u <tenant>` mechanism under a single sub-domain.
src/profile.rs    — `Profile` / `Allowlist` / `Tier` / `Share` / `ShareMode` serde shapes; `parse` (schema-version-checked, validates the `$HOME` prefix-only contract on every `tenant_path`); `expand_tenant_path(name, template) -> PathBuf` resolves the `$HOME` template at the Writer boundary; `default_profile_toml`; `display_path_for` (`~`-rendered form used in plan / echo / error frames).
src/firewall.rs   — pure functions for PF anchor + `/etc/pf.conf` line ops: `render_anchor`, `ensure_anchor_ref`, `remove_anchor_ref`, `is_anchor_referenced`; `tenant_anchor_name` / `_path` centralizers; `ANCHOR_DIR` / `PF_CONF` / `PF_CONF_BACKUP` constants.
src/doctor.rs     — pure functions for the doctor verb: `curated_paths(host, tenant, others)` returns the (Category, AccessMode, PathBuf) probe list; `classify(category, outcome) -> Option<Severity>` maps probe results to finding severity; `has_env_delete_for(policy, var)` parses sudoers for the env_delete directive; `pf_rule_presence_check(rules, tenant)` returns up to two `PfRuleDrift` findings for missing `pass` / `block` rules in a kernel anchor; `has_pam_tid(pam_config)` parses `/etc/pam.d/sudo` for an active `auth sufficient pam_tid.so` directive; `pf_status_enabled(status)` checks pfctl -si output for "Status: Enabled"; `anchor_body_matches(actual, expected)` byte-exact equality on the on-disk anchor body vs the profile-derived render; `has_group_acl_entry(listing, group)` substring-matches `group:<g> allow` in an `ls -lde` listing. `Finding { FilesystemExposure, EnvLeak, PfRuleDrift, TouchIdMissing, PfDisabled, AnchorBodyDrift, AclDrift, SymlinkDrift }` + `SymlinkActual { Absent, WrongTarget(PathBuf), NotSymlink }` (inside `SymlinkDrift` to express the three drift sub-cases) + `Severity { Info, Warning, Critical }` + `Category` types. `Finding::guidance(&self) -> Option<String>` returns the 4-section operator-facing block per variant (Why this matters / Recommended fix / Side-effects / Alternative); `None` for `FilesystemExposure` (per-path guidance folds into the future remediation cycle); `SymlinkDrift` returns case-tailored bodies per `SymlinkActual` variant. All I/O lives in `Writer::doctor_*` orchestration on the executor; this module is grep-and-classify only.
src/reporter.rs   — operator-facing output. Per-verb `_starting` / `_done` methods bake in phrasing and internally branch on (dry_run, verbose); `refuse_*` and `*_failed` methods to stderr; `step(op)` echoes per substrate call in real+verbose; plan rendering flows through `Op::describe_via`. Verbs with a profile-driven plan (mode / shell / reload) split into `_intent` (emits the intent line before the profile read) + `_plan` (renders the plan block after the plan is built) so the operator sees verb context even when read fails. Share-substrate failure framing per arm: `mode_acl_failed` / `mode_account_failed` / `mode_probe_failed` / `refuse_mode_share`; shell variants add "before shell entry"; reload has its own `reload_firewall_failed` / `refuse_reload_share` for verb-specific wording. Reload no-arg form uses `reload_all_starting` / `reload_all_done_summary` to bracket the walk. Create's post-provision arm uses `create_post_provision_*_failed` family that points operator at `tenant reload <name>` for recovery. Doctor uses `doctor_starting` (verbose curated-list block + dry-run intent), `doctor_finding` (one-liner; emits the 4-section guidance block indented 2 spaces under the finding when verbose), `doctor_done_summary`, `doctor_failed` (probe substrate), `doctor_host_file_failed` (sudoers / pam.d/sudo substrate), `doctor_firewall_failed` (pfctl substrate), `doctor_all_tenants_noop`, and `refuse_doctor_*` family.
src/main.rs       — composition root: prod impls + `tenant::run`. Reads `$USER` for the host identity passed to doctor.

tests/cli*.rs            — E2E tests, one binary per verb (`tests/cli_<verb>.rs`) plus `tests/cli.rs` for cross-cutting CLI parser tests. Shared helpers (`NeverExecutor`, `run_with` / `run_with_exec`, `TEST_HOST`, stub builders) live in `tests/common/mod.rs`. Each per-verb file's top-of-file comment describes its scope.
tests/macos_executor.rs  — per-variant pins of the `MacosExecutor::describe_*` argv contract. One test per Account/Profile/Firewall variant so a future tool swap (dseditgroup → dscl . -create; pfctl → some future PF manager) touches one place per op.
tests/macos_reader.rs    — `MacosReader::new()` dscl-integration smoke (`#[cfg(target_os = "macos")]`). Symmetric with macos_executor.rs's per-substrate boundary pin.
tests/doctor.rs          — combinatorial coverage on `doctor::curated_paths` shape, `classify` matrix, `Finding::Display` per-variant byte-form (incl. all 3 `SymlinkActual` sub-cases), `Finding::guidance` per-variant byte-form pins (7 bodied variants — 5 from cycle 9 + AclDrift + 3 SymlinkDrift sub-cases — + the `FilesystemExposure → None` case), `anchor_body_matches` byte-equality cases (equal / extra-newline / empty), and `Severity` ordering (load-bearing for `--strict`).
tests/env_policy_parse.rs — combinatorial coverage on `doctor::has_env_delete_for` (directive shape variants: quoted/unquoted, `+=` vs `=`, single-var vs multi-var list, `Defaults` qualifiers).
tests/pf_rule_parse.rs   — combinatorial coverage on `doctor::pf_rule_presence_check` (empty / pass-only / block-only / both-present, comment / substring / whitespace tolerance, per-tenant naming).
tests/pam_parse.rs       — combinatorial coverage on `doctor::has_pam_tid` (active / commented / wrong-control / wrong-kind / wrong-module / leading-whitespace / truncated-line).
tests/host_acl_parse.rs  — combinatorial coverage on `doctor::has_group_acl_entry` (canonical-bits / pre-canonical-bits / absent / other-group-only / multi-entry / prefix-collision / deny-not-allow / whitespace / commented / empty).
tests/profile_parse.rs   — combinatorial coverage on `profile::parse` (incl. `[[shares]]` table-array shape variants + `$HOME` prefix-only validation) and `profile::expand_tenant_path` (template resolution at the Writer boundary).
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

- **Carve-out methods for non-unit returns** — several Executor
  methods don't fit the `Result<(), E>` shape and are called directly
  by the Writer rather than routed through `WritableOp`: `login(name)
  -> Result<i32, AccountError>` (interactive — inherits stdio so sudo
  can prompt; returns child exit code), `read_profile` /
  `read_pf_conf` / `read_env_policy` / `read_kernel_pf_rules` /
  `read_pam_sudo` / `read_pf_status` / `read_anchor_body` /
  `read_host_acl` (content reads — return type is `String`, not unit);
  `probe_access_as_tenant` / `tenant_path_kind` (probe verdicts —
  return type is the verdict enum, not unit). The `LoginAsUser`
  variant exists in `AccountOp` only for plan/echo rendering via
  `Op::describe_via` — it's intentionally NOT a `WritableOp` impl
  (`execute_account` panics on it). When adding a future executor
  method, ask "does the return fit `Result<(), E>`?" — if yes, ADT
  variant; if no, carve-out.

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

- **Mode-reapply is `InstallAnchor → Reload` + per-share substrate,
  with no flush and no recovery** — `tenant mode <name>
  {install|runtime}` re-renders the anchor body, reloads pf, then
  walks the profile's `[[shares]]` entries (each: `AclOp::Grant` +
  optional `EnsureDirAsUser` parent + `EnsureSymlinkAsUser`). The
  parent `load anchor` directive stays in place across mode reapply,
  so `pfctl -f` re-reads the anchor file and replaces the in-kernel
  ruleset on every reload — no orphan-anchor case, no `FlushAnchor`
  needed. Verified empirically by manual smoke testing (kernel
  `<allowed>` table shrinks back to runtime-tier size on narrow); if
  that ever flips, the fix is one line — insert `FlushAnchor` before
  `InstallAnchor` in `Writer::execute_reapply_plan`. On Reload
  failure, mode does NOT attempt a `RestoreConfigFromBackup`-style
  recovery — the operator reruns the verb (idempotent at the
  substrate). The share pass runs AFTER the PF reapply lands so a
  Reload failure aborts before any ACL/symlink mutation. Negative
  pin in tests: mode flow on a no-shares profile records exactly
  `[InstallAnchor, Reload]` firewall ops — no `FlushAnchor` /
  `BackupConfig` / `RestoreConfigFromBackup` / `RemoveAnchor` /
  `UpdateConfig` / `Enable`. Cycle 10 factored the substrate into
  `Writer::build_reapply_plan` (read profile + parse + pre-flight
  shares + construct the op list) and `Writer::execute_reapply_plan`
  (fires the constructed ops). The verb methods call
  `mode_intent` / `shell_intent` / `reload_intent` BEFORE
  `build_reapply_plan` so the operator sees verb context even when
  the profile read fails, then `mode_plan` / `shell_plan` /
  `reload_plan` to render the upfront plan block over the
  just-constructed ops — every `$` echo line matches a plan line.

- **Shell auto-narrows AND reapplies shares on entry, unconditionally,
  abort-on-failure** — every `tenant shell <name>` runs the full
  profile reapply (PF anchor at runtime tier + per-share Grant +
  EnsureDir + EnsureSymlink) via the shared `build_reapply_plan` +
  `execute_reapply_plan` helpers BEFORE handing off to
  `Executor::login`. The reapply is unconditional (no "are we
  already in runtime?" check) — same structural reasoning as Q2's
  "on-disk anchor is the source of truth" lock; both PF reload and
  every share op (chmod +a, mkdir -p, ln -sfn) are idempotent at
  the substrate. The reapply is also load-bearing: if any step
  fails, the login is NOT launched. `ShellError { Account, Mode }`
  carries the abort posture through to `commands::dispatch`, which
  routes Mode failures through `surface_shell_mode_error` — six
  arms (Profile / Firewall / Acl / Account / Probe / Share) all
  framed as "before shell entry" so the operator sees verb context,
  not mode-verb framing. Operator recovery on a share-substrate
  failure: `tenant reload <name>` (idempotent) or address the
  conflict the Q11/Q12 refusal named. Cycle 10's shell plan grows
  from 3 ops (cycle 4's `InstallAnchor + Reload + LoginAsUser`) to
  3 + per-share ops + LoginAsUser; `shell_intent` emits the intent
  line first (so an operator running against a missing profile still
  sees "Shelling into 'X'." before the read failure), then
  `shell_plan` renders the full op list. Same no-defensive-flush /
  no-auto-recovery posture as the mode verb (the helper is shared);
  negative pin in tests confirms no `FlushAnchor` / `BackupConfig`
  / `RestoreConfigFromBackup` / `RemoveAnchor` ever fires on the
  shell path even when shares are present.

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

- **Exit codes** — `0` success (including destroy's convergent noop,
  the orphan-group convergence path, and doctor's default-mode
  "findings are informational" contract); `64` (`EX_USAGE`,
  sysexits.h) for user-input failure — validation, create-side
  conflict, all refusals (destroy / shell / mode / doctor);
  `74` (`EX_IOERR`) for substrate execution failure on every verb
  except shell. Shell is the exception on its success path: when
  `login` returns Ok, the child shell's exit code propagates as
  tenant's own exit (clamped 0..=255). `1` is clap's default for
  parse errors and `ModeLevel` rejection. Doctor's `--strict`
  carves two more codes from its success path: `1` if findings
  max at warning, `2` if any critical finding; without `--strict`
  doctor always exits `0` on a successful walk.

- **Probe-as-tenant subsumes ACL semantics at the kernel level** —
  doctor's filesystem-exposure detection invokes `sudo -n -u
  <tenant> /bin/test -<r|x> <path>` and treats the kernel's exit
  code as ground truth: 0 → `AccessOutcome::Allowed`, 1 → `Denied`,
  anything else → `Unknown`. The kernel composes POSIX permissions
  + ACLs + sandbox + TCC into the answer, so doctor doesn't need an
  `effective_access(...)` pure function that models macOS ACL
  semantics (including the macOS-specific `read` → `list` /
  `execute` → `search` ACL-rewrite-on-re-read quirk the sandbox
  plugin had to handle). `/bin/test` (not `/usr/bin/test`) is
  load-bearing: macOS Tahoe (Darwin 25.x) and earlier all carry
  `/bin/test`, but `/usr/bin/test` is absent on Darwin 25.x —
  cycle 10's smoke surfaced this as a latent cycle-1 substrate
  bug. Same path applies to cycle 10's `tenant_path_kind` probe.
  Cycle 11's `tenant_path_kind` extension (Symlink target capture
  via readlink) hit the inverse pin: Darwin 25.x ships readlink
  at `/usr/bin/readlink`, not `/bin/readlink` — surfaced by
  cycle 11's smoke (`sudo: /bin/readlink: command not found`).
  No single bin-directory is canonical on macOS; the right
  answer is per-utility: `/bin/test`, `/bin/ln`, `/bin/mkdir`,
  but `/usr/bin/readlink`.
  Cycle-1 design Q3 lock:
  `Denied` doesn't tell the operator WHY (POSIX vs ACL vs
  sandbox); that mechanism reporting is parked for the cycle-2
  remediation surface. Curated list collapses path-not-present
  into the same `Denied` bucket (`test -r /nonexistent` returns
  1) — operator irrelevance is accepted; sub-cycle 6's verbose
  block names every path probed so a `no findings` verdict is
  bounded to THIS LIST.

- **Doctor's curated-path list is bounded and operator-visible** —
  `doctor::curated_paths(host, tenant, others)` returns a fixed
  list; cycle 1 doesn't accept an operator-supplied path glob.
  Bounded scope is the contract: an operator reading "no
  findings" needs to know the audit covers a known set, not
  THEIR whole host. The verbose mode `Reporter::doctor_starting`
  emits "Curated sensitive paths checked for tenant 'X':" + one
  indented `<verb> <path>` line per entry, so the bounded scope
  is explicit when the operator wants the detail. Standard mode
  is silent on the list — most invocations don't need it. A
  future cycle that broadens to user-supplied probe targets must
  preserve the list-it-out semantics on verbose.

- **Doctor's env-leak finding is host-wide, emitted once** —
  `/etc/sudoers` + `/etc/sudoers.d/*` are read once per `tenant
  doctor` invocation (host-level config, not per-tenant) and
  parsed by `doctor::has_env_delete_for` for the
  `SSH_AUTH_SOCK` directive. If absent, doctor emits one
  `Finding::EnvLeak` regardless of which form (`tenant doctor
  <name>` or bare `tenant doctor`) the operator used. The single
  emit lives in `Writer::check_env_leak` and is called once at
  the top of both `doctor_tenant` and `doctor_all_tenants` —
  the all-tenants path does NOT re-check per tenant. Severity is
  `Warning` (not `Critical`) because the leak depends on the
  operator's session env actually carrying the var, and the
  recovery is a one-line sudoers edit named in the finding text.
  Cycle 1 hard-codes `SSH_AUTH_SOCK`; a future cycle may
  generalize to a configurable var list. Env-policy substrate
  uses the `HostFileError` carve-out type (renamed cycle 7 SC1
  from `EnvPolicyError` to cover any host-config-file read —
  sudoers, pam.d/sudo, future /etc/sysctl.conf) so the operator
  sees precise framing when the substrate can't read the file.

- **Only unqualified `Defaults env_delete` counts as protection** —
  sudo's `Defaults` directive supports qualifiers — `Defaults:user`
  scopes to invoking user, `Defaults>runas` scopes to target user
  (`sudo -u`'s arg), `Defaults@host` scopes to host, `Defaults!cmd`
  scopes to a command tag. `has_env_delete_for` accepts ONLY the
  unqualified form. A `Defaults>plugin-dev env_delete += "X"`
  applies only when sudo runs AS `plugin-dev` — it does NOT
  protect `sudo -u <tenant>` invocations, even though the literal
  text mentions `env_delete`. Discovered empirically during cycle
  5's manual smoke: the operator's `/etc/sudoers.d/sandbox-access`
  carried a runas-qualified directive that the original parser was
  treating as universal, masking the actual leak. Negative pins
  for all four qualifier shapes (`:`, `>`, `@`, `!`) live in
  `tests/env_policy_parse.rs`. Tradeoff (Q5 lock): conservative-
  false. An operator with a qualified directive that genuinely
  covers their use case will see a false-positive leak warning;
  recovery is to add an unqualified `Defaults env_delete +=
  "SSH_AUTH_SOCK"` to silence.

- **Doctor doesn't fit the WritableOp shape** —
  `probe_access_as_tenant`, `read_env_policy`,
  `read_kernel_pf_rules`, `read_pam_sudo`, `read_pf_status`, and
  `read_anchor_body` are Executor carve-out methods, NOT `Op<'a>`
  variants. Doctor's probes are how it LEARNS, not what the verb
  does — plan / echo / display dispatch would be inappropriate
  (the operator doesn't need a `$ sudo -n -u tenant test -r
  /Users/host/.ssh/id_rsa` line per probe in verbose; that would
  be ~50 lines per tenant). Same posture as `read_profile` /
  `read_pf_conf` / `login`. The curated list + classify /
  has_env_delete_for / pf_rule_presence_check / has_pam_tid /
  pf_status_enabled / anchor_body_matches / Finding live in
  `src/doctor.rs` (pure functions), the orchestration lives in
  `Writer`. No `Op::Doctor(_)` variant exists.

- **PF rule presence is structural, not exact-match** — cycle 7
  SC2's `pf_rule_presence_check(rules, tenant)` looks for AT LEAST
  one line beginning with `pass ` and AT LEAST one beginning with
  `block ` (after stripping leading whitespace and skipping comment
  lines). Returns up to two `PfRuleDrift` Warning-tier findings.
  Exact line-by-line comparison against the rendered anchor was
  considered (Q7-b lock) and rejected: pfctl's output format isn't
  a stable contract (numerical IPs vs hostnames, table-reference
  reformatting, rule reordering between kernel versions). Structural
  presence catches the case that actually matters — "kernel anchor
  is empty or wrong" — without false-positiving on cosmetic drift.
  Recovery is `tenant mode <name> runtime` (re-renders + reloads
  the anchor); the finding text names that command.

- **Anchor-body drift is file-side, byte-exact, runtime-tier-only** —
  cycle 8's `Finding::AnchorBodyDrift` (Warning) is the file-side
  complement to cycle 7's kernel-side `PfRuleDrift`. The two cover
  independent axes: hand-edited on-disk file vs profile (caught here),
  vs in-kernel anchor diverged from the file (caught by `PfRuleDrift`'s
  structural check). `read_anchor_body` reads `/etc/pf.anchors/tenant-<name>`
  (mode 0644; direct fs read via the `HostFileError` carve-out, same
  posture as `read_pam_sudo`). The comparator `doctor::anchor_body_matches`
  is byte-exact equality vs `firewall::render_anchor(name, runtime_hosts)`;
  the renderer is deterministic, so any difference is real drift, not
  cosmetic. Q9 lock: comparison is RUNTIME tier only — install-tier
  widening outside an active shell session IS drift the operator
  should know about (consistent with cycle 4's session-scoped doctrine,
  where `tenant shell <name>` auto-narrows on entry). Q4 lock: a
  profile that can't be read or parsed SKIPS the check silently (no
  spurious `AnchorBodyDrift`); a future cycle's `ProfileMissing` finding
  would surface that case separately. Wired in `Writer::probe_tenant_paths`
  via the private `check_anchor_body_drift` helper. Recovery is
  `tenant mode <name> runtime`; the finding text names that command.

- **Touch-ID-for-sudo is Info-tier, not Warning** — cycle 7 SC3's
  `Finding::TouchIdMissing` (emitted host-wide once per `tenant
  doctor` invocation) is Info severity per the Q5 lock. The
  rationale: Touch ID for sudo is a recommendation aligned with the
  project's locked NOPASSWD-sudoers stance (Touch ID makes sudo
  faster AND adds an auth factor), not a correctness drift. Info
  findings do not trip `--strict`'s exit-1, so the operator sees
  the one-time tip without `tenant doctor --strict` nagging on
  every run. `has_pam_tid` accepts only `auth sufficient pam_tid.so`
  (conservative-false: `required` or `optional` controls report
  as missing because their pam.d semantics don't carry the same
  short-circuit-on-success UX guarantee).

- **PfDisabled is Critical, host-wide, one emit per invocation**
  — cycle 7 SC4's `Finding::PfDisabled` fires when `pfctl -si`
  doesn't report `Status: Enabled`. When pf is globally disabled,
  NO tenant's anchor is enforcing — every tenant's firewall is
  silently inert (the in-memory rule store still has entries; they
  just aren't consulted on packet filtering). Critical severity is
  load-bearing: this is the only doctor finding that says "your
  isolation guarantee is currently zero." Recovery is `sudo pfctl
  -e` (idempotent at the substrate; same command the create flow's
  `FirewallOp::Enable` runs). Like the env-leak and Touch-ID
  checks, it's host-level and emits once per `tenant doctor`
  invocation regardless of how many tenants are walked.

- **HostFileError covers multiple host-config substrates** —
  renamed cycle 7 SC1 from `EnvPolicyError`. The shape (`Spawn` /
  `NonZero` / `Fs`) fits any privileged-or-cheap host-config-file
  read: sudoers + drop-ins via `read_env_policy` (privileged,
  uses sudo cat), pam.d/sudo via `read_pam_sudo` (mode 0644,
  direct fs read). A future check that reads /etc/sysctl.conf or
  a launchd plist would reuse this type rather than introducing a
  new error type per substrate. The Reporter's
  `doctor_host_file_failed` frame is path-agnostic ("failed to
  read host config: {err}") — the error's Display impl names the
  specific path / process detail.

- **Finding guidance is a 4-section block gated on `-v`** — cycle
  9 added `Finding::guidance(&self) -> Option<String>` returning a
  flat (column-0 headers, column-2 body, no trailing newline) text
  with section order Why this matters → Recommended fix →
  Side-effects to know about → Alternative. `Reporter::doctor_finding`
  prefixes every non-empty guidance line with 2 spaces under the
  finding line in verbose mode; blank lines emit as bare newlines
  (no trailing whitespace). Standard mode emits the one-liner only
  — the verbose disclosure is opt-in to keep skim-the-output usage
  unchanged. Style locks: sentence-case headers, imperative voice
  in the fix command's justification line, literal tenant name in
  per-tenant variants' "why" + "fix" prose so the operator's
  grep-the-output workflow surfaces the right tenant. Variants
  without a meaningful different command (TouchIdMissing,
  PfDisabled) omit Alternative; the comment in `src/doctor.rs`
  names the rationale at the variant. `FilesystemExposure` returns
  `None` (Q3 lock): per-path guidance text depends on file-vs-dir
  + intent + POSIX-vs-ACL fix; folds into the eventual
  filesystem-exposure remediation cycle alongside the ACL
  machinery. New `Finding` variants must author their `guidance()`
  body at introduction time AND ship a per-variant byte-form pin in
  `tests/doctor.rs` — these two together are the contract that the
  operator-facing surface stays educational, not just diagnostic.

- **Per-tenant `[[shares]]` are profile-driven, not CLI-driven** —
  cycle 10's filesystem-share substrate: the per-tenant profile
  TOML grows an optional `[[shares]]` table-array, each entry a
  `(host_path, mode {ro|rw}, tenant_path)` triple. Source of truth
  is the profile; the operator hand-edits it and runs `tenant
  reload <name>` to reconcile (matches sandbox-plugin posture and
  the existing PF-allowlist doctrine). Per-tenant, not host-wide
  (matches the isolation model: different tenants get different
  group ACLs, hence different reachable paths). `host_path` is
  literal absolute; `tenant_path` is a template with `$HOME`
  prefix-only resolution (Q3 lock — `$HOME` expands to
  `/Users/<tenant>` only when at position 0; mid-string `$HOME`
  refuses at parse with `tenant_path "..." contains \`$HOME\` not
  at the start`). Mode values `"ro"` / `"rw"` (Q1 lock — string
  discriminator; POSIX bit-string forms rejected because file vs
  directory POSIX semantics diverge). Q11 + Q12 pre-flights run
  BEFORE any substrate op: `host_path.exists()` (operator-process
  check) + `tenant_path_kind` (sudo-u probe) reject
  `ShareError::HostPathMissing { path }` and
  `ShareError::TenantPathOccupied { path }` respectively — the
  substrate NEVER clobbers operator data at a `tenant_path` that
  exists as a real directory or file. Cycle 10 deliberately does
  NOT auto-revoke ACLs from removed share entries (Q14 lock); a
  future cycle 11 doctor extension surfaces orphans.

- **`AclOp` sub-domain — mechanism-named, chmod-+a-natively-idempotent**
  — `AclOp::Grant { path, group, mode }` and `AclOp::Revoke { ...
  }` map to `chmod +a/-a "group:<g> allow <bits>" <path>` (no
  sudo prefix — operator owns or has ACL-write on host_path).
  `AclMode { Ro, Rw }` (executor-vocab) is the substrate sibling
  of `profile::ShareMode { Ro, Rw }` — the Writer translates at
  the layer boundary. The bit lists are ported verbatim from
  sandbox's `acl.py`: ro = `read,execute,file_inherit,directory_inherit`;
  rw = `read,write,execute,delete,append,file_inherit,directory_inherit`.
  macOS chmod +a is NATIVELY idempotent: re-applying the same
  entry to a path that already carries it neither errors nor
  duplicates — verified by cycle-10 smoke (count stays at 1 across
  sequential reloads). An earlier draft of `execute_acl` tried a
  substring-match pre-check against `ls -lde` output, but macOS
  canonicalizes the bit names on storage (`read,write,execute,delete,append`
  → `list,add_file,search,delete,add_subdirectory`), so the
  pre-check always failed false-negative. Removed the dead
  pre-check; the operator-visible behavior is unchanged.
  `AclError { Spawn, NonZero }` is the domain error type. Revoke
  (`chmod -a`) on an absent entry currently surfaces as
  `AclError::NonZero` ("No matching ACL entry"); no cycle-10 path
  exercises Revoke, so cycle 11's doctor ACL-drift remediation
  will need to tolerate that case if/when it ships.

- **`EnsureDirAsUser` and `EnsureSymlinkAsUser` substrate-group
  with `LoginAsUser`** — three `AccountOp` variants share the
  `sudo -n -u <tenant> <cmd>` mechanism (run AS the tenant, not
  as the operator). Mapped to `sudo -n -u <name> /bin/mkdir -p
  <path>` and `sudo -n -u <name> /bin/ln -sfn <target> <link>`
  respectively. Both reuse `AccountError` (same shape as
  sysadminctl / dseditgroup failures). Grouping under `AccountOp`
  rather than introducing a `FilesystemAccessOp` is doctrinal:
  the substrate mechanism (sudo-u) is what's shared. The Writer
  skips the `EnsureDirAsUser` op when the tenant_path's parent
  IS the tenant home dir itself (`/Users/<name>` — always
  exists, mkdir would be a no-op).

- **`tenant_path_kind` carve-out** — cycle 10's pre-flight probe
  for Q12. `sudo -n -u <tenant> /bin/test -L <path>` (symlink
  check) + `-e` (existence check) collapse into one of `PathKind {
  Absent, Symlink, Other }`. Substrate-machinery failures (sudo
  auth cache miss, fork failed) surface as `ProbeError` (same type
  as `probe_access_as_tenant` — the carve-out posture mirrors
  doctor's probe machinery). Used by `Writer::build_share_ops` to
  refuse `TenantPathOccupied` when kind is `Other`; `Symlink` is
  the idempotent re-link case the substrate proceeds through.
  Like `probe_access_as_tenant`, this is a CARVE-OUT method (return
  type isn't `Result<(), E>` so it doesn't fit `WritableOp`).

- **`ReapplyPlan` + `ShareOps` are the pre-built op list** —
  cycle 10's plan/echo asymmetry fix: profile-driven plans
  construct the full op list FIRST (`Writer::build_reapply_plan`:
  read + parse + pre-flight shares + build PF and per-share ops),
  emit the plan over the constructed ops, THEN execute the same
  ops (`Writer::execute_reapply_plan`). `ReapplyPlan {
  install_anchor, reload, share_ops }` + `ShareOps { grant,
  ensure_dir, ensure_link }` own the constructed values so the
  borrowed `Op<'_>` slice the Reporter renders survives the
  execution phase. `execute_share_ops` is the per-share loop
  body shared by `execute_reapply_plan` (mode/shell/reload) and
  `reapply_shares_post_provision` (create's post-Enable step,
  which skips PF because the create-time firewall sequence
  already ran it). The intent line (`mode_intent` /
  `shell_intent` / `reload_intent`) is emitted BEFORE the
  profile read so the operator sees verb context even on
  profile-read failure (cycle-4 invariant extended to mode +
  reload in cycle 10 round 2).

- **`tenant reload [<name>]` — the operator-facing "I edited
  config, apply it" verb** — cycle 10's headline verb. Single-
  tenant form runs the full reapply (PF + shares) at runtime
  tier; no tier-swap (the operator uses `tenant mode <name>
  install` for that). No-arg form walks every tenant from
  `Reader::tenant_names()` in alphabetical order; per-tenant
  failures don't abort the walk — the verb continues,
  accumulates, and surfaces a single end-of-walk summary line
  (`Reloaded N of M tenant(s); F failed.`). Exit 0 on a clean
  walk, EX_IOERR (74) on any per-tenant failure (Q15 lock).
  Empty-host case emits "No tenants on this host to reload."
  `Verb::Reload { name: Option<String> }`; dispatch parallels
  `Doctor`'s no-arg form. The verb-name was locked via
  `naming:naming-things` in the design conversation — `reload`
  wins over `apply` / `refresh` / `reconcile` / `sync` /
  `converge` on operator-familiarity + accurate intent-mapping.

- **`CreateError::PostProvision(ModeError)` — share-substrate
  failure after PF + Enable lands** — cycle 10's create-time
  share reapply runs after user + group + profile + PF + Enable
  all succeed. Default profile has no `[[shares]]` so this is a
  no-op on the production path; tests using
  `with_create_profile_content` to pre-populate a profile with
  shares exercise the arm. When it fires, the host has a fully-
  provisioned tenant but a substrate failure on Acl/Account/Probe/
  Share. Recovery is `tenant reload <name>` (idempotent retry),
  NOT another `tenant create` (which would refuse on
  name-conflict). The Reporter framing names this explicitly:
  `'<name>' provisioned but ... ; recover with \`tenant reload
  <name>\``. The post-provision step uses
  `reapply_shares_post_provision` (skips PF; the create-time
  firewall sequence already ran it) rather than the full
  `build_reapply_plan` + `execute_reapply_plan`.

- **`Finding::AclDrift` + `Finding::SymlinkDrift` — per-tenant
  share-drift detection (cycle 11)** — `Writer::check_share_drift`
  walks `parsed_profile.shares` and emits two independent findings
  per share: `AclDrift { tenant, host_path, group }` when
  `read_host_acl(host_path)` doesn't carry the
  `<tenant>-tenant-share` group's `allow` entry; and
  `SymlinkDrift { tenant, tenant_path, expected_target, actual }`
  when `tenant_path_kind` returns a state that doesn't match the
  declared `host_path` symlink. Both Warning-tier; recovery is
  `tenant reload <name>` (cycle 10's substrate is idempotent).
  Bounded scope — set of audited paths comes from the profile,
  not from filesystem walking; orphan-ACL detection (entry on a
  path whose share was removed from the profile) is parked. Q3
  lock: target comparison is string-exact (no `fs::canonicalize`)
  — the operator's declared path is what's compared. Q4 lock:
  `NotSymlink` is a `SymlinkActual` case inside `SymlinkDrift`,
  NOT a separate `Finding` variant — all three sub-cases express
  "symlink isn't what was declared", case-tailored guidance per
  variant (`tenant reload` recovers Absent + WrongTarget; manual
  cleanup first for NotSymlink because cycle-10 Q12's
  `TenantPathOccupied` refusal would otherwise fire on reload).
  Q5 lock: per-share substrate failure (read_host_acl or
  tenant_path_kind) aborts the walk via `DoctorError::Probe`
  (same fail-fast posture as `read_kernel_pf_rules`). Q6 lock:
  `--fix` stays parked per cycle 9's "tell, don't fix" doctrine.

- **`PathKind::Symlink(PathBuf)` — carries resolved target**
  (cycle 11 extension) — cycle 10 introduced `PathKind { Absent,
  Symlink, Other }` for `tenant_path_kind`'s pre-flight; cycle 11
  extended `Symlink` to carry the readlink target so doctor's
  `SymlinkDrift` can compare against the declared `host_path` in
  one substrate trip. `MacosExecutor::tenant_path_kind` calls
  `sudo -n -u <tenant> /usr/bin/readlink` after the `/bin/test -L`
  hit and stores the raw target verbatim (no canonicalization, no
  resolution of intermediate symlinks). Cycle-10's call sites
  (`Writer::build_share_ops`) only check `matches!(kind,
  PathKind::Other)`, so the variant extension didn't ripple
  through behavior — just type-level honesty about what the
  Symlink case carries. Removed the `Copy` derive (PathBuf isn't
  Copy); StubExecutor's `tenant_path_kinds` map uses `.cloned()`.

- **`read_host_acl(path)` — operator-process `ls -lde`** (cycle 11
  carve-out) — reads host-side ACL state from the operator process
  (no sudo). Substrate posture matches `host_path.exists()` (Q11
  cycle 10) — host-side state, read from the operator process.
  Reuses `ProbeError` (same posture as `probe_access_as_tenant`:
  machinery failures are errors; "entry not present" is a
  non-error outcome the parser turns into a no-finding). Doctor
  parses via `doctor::has_group_acl_entry(listing, group) ->
  bool`, which substring-matches `group:<g> allow` in the listing.
  Looser than substring-matching the full canonical entry — macOS
  canonicalizes ACL bits on storage (`read,write,execute,delete,
  append` → `list,add_file,search,delete,add_subdirectory`), so
  bit-list comparison would false-negative. Word-boundary
  discipline via the ` allow` suffix prevents prefix-collision
  (`group:dev allow` doesn't match a query for `dev-tenant-share`).

- **DryRun share-drift is structurally skipped, not synthesized**
  (cycle 11) — `DryRunExecutor::read_profile` returns
  `default_profile_toml()` (no `[[shares]]`), so doctor's per-share
  loop body never executes under production dry-run regardless of
  the underlying stub's profile state. No per-substrate "synthetic
  no-drift" needed on `DryRunExecutor::read_host_acl` /
  `tenant_path_kind` for the AclDrift / SymlinkDrift findings. The
  defensive returns (empty listing, Absent kind) cover the
  hypothetical future case where the default profile grows a share.

- **Acronym casing** — Rust convention treats acronyms as words:
  `Uid` not `UID`, `Macos` not `MacOS`. Methods are
  `lowest_free_uid`, struct is `UidAllocator`, `MacosReader`.

- **Clap flag scoping** — `-v / --verbose` and `--dry-run` are both
  `global = true` on `Cli` (accept either before or after the
  subcommand). Per-subcommand flags (e.g. `--strict`, `--json`,
  `--yes`) stay scoped to their verb.

## Test discipline

E2E-first. The bulk of tests live in `tests/cli_<verb>.rs` (one file
per verb) and drive through `tenant::run` with a `StubReader`.
`tests/cli.rs` retains cross-cutting CLI parser tests. Shared helpers
(`NeverExecutor`, `run_with` / `run_with_exec`, stub builders) live in
`tests/common/mod.rs`, pulled in via `mod common; use common::*;`.
Inline `#[cfg(test)] mod tests` blocks are out of style on this
project; standalone unit-test files need explicit justification —
`tests/macos_executor.rs` and `tests/macos_reader.rs` are the
canonical precedents for per-substrate boundary pins (argv contract
for the executor; dscl-translation smoke for the reader).
`tests/profile_parse.rs`, `tests/firewall_render.rs`,
`tests/firewall_conf.rs`, `tests/doctor.rs`,
`tests/env_policy_parse.rs`, `tests/pf_rule_parse.rs`, and
`tests/pam_parse.rs` each carry the same justification:
combinatorial coverage on a pure function (`parse` +
`expand_tenant_path`, `render_anchor`,
`ensure_anchor_ref` / `remove_anchor_ref` / `is_anchor_referenced`,
`curated_paths` / `classify` / `Finding::Display` /
`anchor_body_matches`, `has_env_delete_for`,
`pf_rule_presence_check`, `has_pam_tid`) whose call sites are
inside the writer and would otherwise need many overlapping E2E
tests. Per-variant or per-shape unit testing is the right tool
when the function's state space is combinatorial; CLI E2E remains
the default for verb-level behavior.

Two helpers in `tests/common/mod.rs`: `run_with(stub, args) -> (u8,
String, String)` wires a `NeverExecutor` (panics if any substrate
method is called — guards "should not touch the host" paths like
dry-run / validation / conflict). `run_with_exec(stub, &StubExecutor,
args)` lets the test own the executor for real-mode assertions on op
shape / configured failure. Both run the binary in-process and return
exit code + stdout + stderr as `String`s.

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
