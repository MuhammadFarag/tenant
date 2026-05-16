# tenant — Rust port of the macOS tenant-account CLI

A small CLI for provisioning macOS user accounts, primary groups (named
`<name>-tenant-share`) in a project-reserved UID/GID range (≥600), a
per-tenant profile (TOML at `~/.config/tenant/profiles/<name>.toml`),
and a per-tenant PF anchor (`/etc/pf.anchors/tenant-<name>` referenced
from `/etc/pf.conf`).

Verbs:
- `tenant create <name>` — provision user + share group + profile + PF
  anchor; enables pf.
- `tenant destroy <name>` — symmetric teardown; convergent (absent ⇒
  noop; orphan-group ⇒ converges); ends with `pfctl -a tenant-<name>
  -F all` to flush in-kernel rules.
- `tenant mode <name> install|runtime` — re-render anchor at the
  requested allowlist tier + reload pf; widens egress for install-tier
  work, narrows back when done.
- `tenant shell <name>` — auto-narrows to runtime tier AND reapplies
  the profile's `[[shares]]` before launching the login shell, so any
  leftover install-tier widening or operator-clobbered ACL/symlink is
  session-scoped.
- `tenant reload [<name>]` — config-driven "I edited the profile,
  apply it": rewrites anchor at runtime + reapplies shares. No-arg
  walks every tenant; exits 0 clean / 74 on any failure.
- `tenant doctor [<name>]` — read-only audit: probes curated host
  paths AS the tenant; reads sudoers (env_delete), pam.d/sudo
  (Touch-ID-for-sudo), `pfctl -si` (pf enabled), `pfctl -a tenant-<name>
  -sr` (rule presence), on-disk anchor body (file drift), host ACLs
  + symlink targets (share drift), group membership. `--strict` maps
  max severity to exit 1 (warning) / 2 (critical).

Rust port of an earlier Go prototype (at `/Users/plugin-dev/src/tenant/`
for cross-reference); follows Rust idioms (clap derive, composition-root
DI, trait-object Reader) rather than mirroring the Go shape.

## Scope

This file carries the stable doctrine and file map — facts about what
the code *currently does*. For the chronology of shipped versions,
`git log --oneline` walks the commits.

## File map

```
src/lib.rs        — public API (`run`); `Cli` + `Verb` (Create / Destroy / Shell / Mode / Doctor / Reload) + `ModeLevel`; global `--verbose` / `--dry-run` / `--yes`. `run` takes `host: &str` + `stdin: &mut dyn BufRead` + `stdin_is_tty: bool` + `colors: ansi::Colors`. Swaps to `DryRunExecutor` when `--dry-run`.
src/ansi.rs       — internal ANSI wrapper. `Colors { stdout, stderr }` per-stream gate via `Colors::detect()`; wrappers `red`/`green`/`yellow`/`cyan`/`bold`/`dim`; `rule(title, width)` for the section divider; `panel` exists but unused.
src/commands.rs   — verb dispatch (`match` on `Verb`). No I/O; routes to Reporter. `doctor_exit_code(severity, strict)` → 0/1/2. Helpers `surface_destroy_error` / `surface_doctor_error` / `surface_mode_error` / `surface_shell_mode_error` / `surface_reload_error` / `surface_create_post_provision_error` centralize per-arm Reporter routing. Plan-op builders (`build_create_plan_ops` / `build_destroy_plan_ops` / `build_orphan_plan_ops`) construct the verbose plan; for `mode` / single-tenant `reload`, dispatch calls `Writer::build_reapply_plan` upfront so profile-read failures surface pre-prompt. Each mutating verb calls `Writer::pre_exec_doctor_summary` with the verb-appropriate `DoctorScope` between summary and confirm.
src/accounts.rs   — `Reader` trait + Macos/Stub impls; `Writer` verb methods (`create_tenant`, `destroy_tenant`, `destroy_orphan_group`, `shell_into_tenant`, `apply_tenant_mode`, `reload_tenant`, `reload_all_tenants`, `doctor_tenant`, `doctor_all_tenants`, `pre_exec_doctor_summary`). Shared `build_reapply_plan` + `execute_reapply_plan` drive mode/shell/reload; `reapply_shares_post_provision` skips PF for create's post-Enable share pass; `execute_share_ops` is the shared per-share loop. Doctor helpers: host-wide `check_env_leak` / `check_touch_id_for_sudo` / `check_pf_status` (single-emit per invocation) + per-tenant `probe_tenant_paths` (curated probes + structural pf-rule check + `check_anchor_body_drift` + per-share `check_share_drift`); `collect_share_drift` is the quiet sibling for the inline audit. `DoctorScope { Create, Shell, Mode, Reload }`. `validate_name` / `check_conflict` / `destroy_eligibility`; `tenant_share_group_name`. `Writer::run<O: WritableOp>` couples per-step echo + execute. `ReapplyPlan` + `ShareOps` carry the pre-built op list. Errors: `ShareError { HostPathMissing, TenantPathOccupied }`, `ModeError { Profile, Firewall, Acl, Account, Probe, Share }`, `CreateError::PostProvision(ModeError)`, `CreateError::HostMembership(AccountError)`, `ReloadAllOutcome { failed }`, `DoctorOutcome` + `DoctorError { Probe, HostFile, Firewall }`.
src/allocation.rs — `UidAllocator` + `GidAllocator`. Independent; both iterate from `TENANT_UID_FLOOR = 600`.
src/executor.rs   — `Op` ADT over `AccountOp` / `ProfileOp` / `FirewallOp` / `AclOp`; `WritableOp` trait; `Op::describe_via(executor)` (substrate echo), `Op::business_label()` (past-tense ✓ progress), `Op::intent_label()` (future-tense `• <intent>` plan-bullet). `Executor` trait: per-domain `describe_*` / `execute_*` pairs + non-unit carve-outs (`login`, `read_profile`, `read_pf_conf`, `probe_access_as_tenant`, `read_env_policy`, `read_kernel_pf_rules`, `read_pam_sudo`, `read_pf_status`, `read_anchor_body`, `read_host_acl`, `tenant_path_kind`, `host_in_group`). Impls: `MacosExecutor` / `StubExecutor` / `DryRunExecutor`. Errors: `AccountError` / `ProfileError` / `FirewallError` / `ProbeError` / `HostFileError` (sudoers, pam.d/sudo, on-disk anchor) / `AclError`. Enums: `AccessMode { Read, List }`, `AccessOutcome { Allowed, Denied, Unknown }`, `PathKind { Absent, Symlink(target: PathBuf), Other }`, `AclMode { Ro, Rw }`. `AccountOp::LoginAsUser` / `EnsureDirAsUser` / `EnsureSymlinkAsUser` substrate-group the `sudo -n -u <tenant>` mechanism.
src/profile.rs    — `Profile` / `Allowlist` / `Tier` / `Share` / `ShareMode` serde shapes; `parse` (schema-version + `$HOME` prefix-only validation); `expand_tenant_path(name, template) -> PathBuf`; `default_profile_toml`; `display_path_for` (`~`-rendered form).
src/firewall.rs   — pure functions: `render_anchor`, `ensure_anchor_ref`, `remove_anchor_ref`, `is_anchor_referenced`; `tenant_anchor_name` / `_path`; constants `ANCHOR_DIR` / `PF_CONF` / `PF_CONF_BACKUP`.
src/doctor.rs     — pure functions: `curated_paths(host, tenant, others)`; `classify(category, outcome) -> Option<Severity>`; `has_env_delete_for(policy, var)`; `pf_rule_presence_check(rules, tenant)`; `has_pam_tid(pam_config)`; `pf_status_enabled(status)`; `anchor_body_matches(actual, expected)`; `has_group_acl_entry(listing, group)`. `Finding { FilesystemExposure, EnvLeak, PfRuleDrift, TouchIdMissing, PfDisabled, AnchorBodyDrift, AclDrift, SymlinkDrift, HostNotInShareGroup }` + `SymlinkActual { Absent, WrongTarget(PathBuf), NotSymlink }` + `Severity { Info, Warning, Critical }` + `Category`. `Finding::guidance(&self) -> Option<String>` returns the 4-section operator-facing block (Why this matters / Recommended fix / Side-effects / Alternative); `None` for `FilesystemExposure`. All I/O in `Writer::doctor_*`; this module is grep-and-classify only.
src/reporter.rs   — operator-facing output. Substrate vocab `ok(msg)` (✓ green) + `section(title)` (`─── <title> ───`). Per-verb `_starting` / `_done` branch on (dry_run, verbose); `_starting` emits the section divider; `_done` emits `─── Done ───` + a single enriched closing line. Per-step success: `progress(op)` → `ok(op.business_label())`; `$` echo via `step(op)` (real+verbose). `mode_intent` / `reload_intent` section-only; `shell_intent` + `shell_plan` survive (no prompt). Pre-execution: per-verb `*_summary(name, ..., plan: Option<&[(Op, Option<&str>)]>)` emits headline + capability bullets + (verbose + `plan = Some`) `Plan (commands to execute):` + sudo-needed-for line. `shell_summary(name, host)` (no plan slot). `render_plan_block`: `  • <intent>[  # <annotation>]` + indented shell line (privilege-aware: bold `sudo` + dim rest, else all-dim). `confirm(...) -> ConfirmOutcome { Proceed, Abort }`; `aborted()` → "Aborted by operator. No changes made." `doctor_finding` colors severity; bold-headers + dim-body for verbose guidance. `doctor_finding_one_liner` (no guidance) + `doctor_summary_pending(count, target)` (`⚠ Doctor: …`, silent on 0) drive the inline pre-exec audit. `refuse_*` / `*_failed` plain on stderr. Reload no-arg: `reload_all_starting` / `reload_all_done_summary`. Create's post-provision: `create_post_provision_*_failed` points at `tenant reload <name>`.
src/main.rs       — composition root: prod impls + `tenant::run`. Reads `$USER`; probes stdin TTY + colors.

tests/cli*.rs            — E2E tests, one binary per verb (`cli_<verb>.rs`) plus `cli.rs` for CLI parser cross-cutting; shared helpers in `tests/common/mod.rs`.
tests/macos_executor.rs  — per-variant pins of `MacosExecutor::describe_*` argv contract.
tests/intent_labels.rs   — per-variant byte-form pins of `Op::intent_label()`; sharpening pin that `intent_label` ≠ `business_label` for `LookupUserRecord` / `DeleteUserRecord`.
tests/macos_reader.rs    — `MacosReader::new()` dscl-integration smoke (`#[cfg(target_os = "macos")]`).
tests/doctor.rs          — combinatorial: `curated_paths`, `classify` matrix, `Finding::Display` byte-form (incl. all 3 `SymlinkActual` sub-cases), `Finding::guidance` byte-form, `anchor_body_matches`, `Severity` ordering (load-bearing for `--strict`).
tests/env_policy_parse.rs — combinatorial on `has_env_delete_for` (quoted/unquoted, `+=` vs `=`, single-var vs list, `Defaults` qualifiers).
tests/pf_rule_parse.rs   — combinatorial on `pf_rule_presence_check`.
tests/pam_parse.rs       — combinatorial on `has_pam_tid`.
tests/host_acl_parse.rs  — combinatorial on `has_group_acl_entry` (canonical / pre-canonical bits / absent / other-group / multi-entry / prefix-collision / deny / whitespace / commented / empty).
tests/profile_parse.rs   — combinatorial on `parse` (incl. `[[shares]]` shape variants + `$HOME` prefix-only) and `expand_tenant_path`.
tests/firewall_render.rs — combinatorial on `render_anchor`.
tests/firewall_conf.rs   — combinatorial on `ensure_anchor_ref` / `remove_anchor_ref` / `is_anchor_referenced`.
```

## Project doctrine

Things that are easy to violate and would matter:

- **Intent / mechanism split** — domain ops (`AccountOp` /
  `ProfileOp` / `FirewallOp` / `AclOp`) express *what*;
  `MacosExecutor` owns argv. Writer never constructs argv; tests
  assert on op identity (`exec.account_ops()[N] ==
  AccountOp::CreateShareGroup{..}`); literal shell-command shape
  pinned narrowly in `tests/macos_executor.rs` — one test per
  variant, so a future tool swap moves one place per op.
  Operator-facing output also splits two-tier: each verb has a
  `_starting` / `_done` pair on `Reporter` branching on (dry_run,
  verbose). Plans are `&[(Op<'_>, Option<&'static str>)]` —
  annotation slot carries `# on rollback` / `# on reload failure`.
  Conditional steps appear in the upfront plan unconditionally
  but echo via `Reporter::step` only when they actually run —
  plan-vs-echo asymmetry signals a skipped conditional.
  Interactive verbs (`shell`) use `_starting`-only.

- **One Executor trait; sub-domains live as method-pairs** —
  `Op<'a>` wraps `&AccountOp` / `&ProfileOp` / `&FirewallOp` /
  `&AclOp`. Display through `Op::describe_via(executor)`; execution
  via `WritableOp::execute_via`, preserving per-domain error types
  end-to-end (`CreateError::Group(AccountError)` etc.). Adding a
  future sub-domain extends `Executor` with a new `describe_*` /
  `execute_*` pair plus a leaf variant — no new trait. The single
  `Executor` is the one test seam at the host boundary.

- **Carve-out methods for non-unit returns** — Executor methods
  that don't fit `Result<(), E>` are called directly by Writer:
  `login` (interactive, inherits stdio, returns child exit code),
  content reads (return `String`), probe verdicts (return enum /
  bool). `AccountOp::LoginAsUser` exists only for plan/echo render
  (`execute_account` panics on it). Future method: returns fit
  `Result<(), E>`? — yes ⇒ ADT variant; no ⇒ carve-out.

- **Interactive verbs use `login`, not `execute_account`** —
  `execute_account` captures stdout/stderr (suppresses sysadminctl
  chatter on success, surfaces it via `AccountError::NonZero` on
  failure — right for batch verbs); `login` inherits parent stdio
  so sudo can prompt and the launched shell drives the controlling
  terminal. `AccountError` is reserved for `login` *spawn*
  failures; child exit codes propagate via the i32 return.

- **Probe via Executor, not Reader live re-read** — when a verb
  needs to re-check OS state mid-execution (destroy's
  `LookupUserRecord` residue probe is canonical), it's a regular
  substrate call whose `Ok(())` vs `Err(AccountError::NonZero{..})`
  drives a Writer branch. Reader stays snapshot-then-act —
  in-memory view captured at composition-root. Don't add "live
  re-read" to Reader.

- **No I/O in command logic** — `commands::dispatch` and
  `accounts::Writer` call Reporter's verb-named methods; neither
  touches raw writers nor checks `cli.verbose` / `cli.dry_run`.
  Mode/verbosity branching lives inside Reporter.

- **Lexical → state-based check order** — `validate_name`
  (charset) runs before `check_conflict` / `destroy_eligibility`
  (OS state). Cheaper failure first.

- **Convergent semantics for teardown verbs** — `destroy <name>`
  against an absent tenant is a successful noop. When user is
  absent but a stale `<name>-tenant-share` group remains,
  `destroy_eligibility` returns `OrphanGroup` and dispatch routes
  to `Writer::destroy_orphan_group` to converge. Orphan path runs
  the full PF teardown (each step idempotent), so partial-firewall
  state from a failed earlier create also converges.

- **`<name>-tenant-share` / `tenant-<name>` are centralized** —
  `accounts::tenant_share_group_name(name)` (group suffix);
  `firewall::tenant_anchor_name(name)` (anchor prefix). Don't
  inline `format!` at call sites.

- **Decoupled UID/GID allocation** — `UidAllocator` reads
  `used_uids`, `GidAllocator` reads `used_gids`; the two spaces
  are disjoint and may legitimately diverge (UID 613, GID 600 on
  a host with prior tenants). Don't fuse them.
  `verbose_uid_and_gid_allocators_cross_over` pins divergence.

- **Create partial-failure rollback / recovery posture** —
  `CreateError::{Group, User, UserWithRollback, Profile, Firewall,
  HostMembership, PostProvision}`. `UserWithRollback` emits two
  Reporter calls (original error + em-dash-suffixed rollback-failed
  hint). Profile/Firewall failures leave user + group (+ partial
  PF) on host; recovery is `tenant destroy <name>` (idempotent on
  PF, so partial anchor state converges). On PF Reload failure,
  Writer runs an automatic 4-step recovery (RestoreConfigFromBackup
  → RemoveAnchor → Reload → FlushAnchor) BEFORE surfacing the
  error; recovery-of-recovery surfaces as
  `FirewallError::RestoreFailed { path }` with a manual-recovery
  hint naming the backup path and `sudo cp`. `PostProvision(ModeError)`
  recovers via `tenant reload <name>` (NOT another `tenant create`
  — would refuse on name-conflict).

- **PF anchor flush is load-bearing on destroy paths** — `pfctl -f
  /etc/pf.conf` does NOT garbage-collect anchors whose `load
  anchor` directive has been removed. Without `pfctl -a
  tenant-<name> -F all`, the previous tenant's rules persist in
  kernel memory under an orphan name; the next tenant getting the
  same UID silently inherits them. `FirewallOp::FlushAnchor` is
  the final step on both destroy paths and on create-side
  reload-failure recovery. Tests pin "FlushAnchor is last on both
  destroy paths" AND "create's success path does NOT invoke
  FlushAnchor". Load-bearing-ness is specific to "parent directive
  removed"; defensive-flush would blur the principle.

- **Mode/shell/reload share `build_reapply_plan` +
  `execute_reapply_plan`** — all three reapply the profile (PF
  anchor at the requested tier + per-share `AclOp::Grant` +
  optional `EnsureDirAsUser` + `EnsureSymlinkAsUser`). The parent
  `load anchor` directive stays in place across reapply, so
  `pfctl -f` re-reads and replaces the in-kernel ruleset — no
  orphan-anchor case, no `FlushAnchor` needed. On Reload failure,
  no `RestoreConfigFromBackup` recovery — operator reruns
  (idempotent). Negative pin: mode on a no-shares profile records
  exactly `[InstallAnchor, Reload]` firewall ops. Factoring:
  `build_reapply_plan` (read profile + parse + pre-flight shares
  + construct op list) + `execute_reapply_plan` (fires ops);
  share pass runs AFTER PF reapply lands so a Reload failure
  aborts before any ACL/symlink mutation. `ReapplyPlan` +
  `ShareOps` own the constructed values so the borrowed `Op<'_>`
  slice survives execution. `execute_share_ops` shared with
  `reapply_shares_post_provision` (create's post-Enable, skips PF).

- **Shell auto-narrows AND reapplies shares on entry,
  unconditionally, abort-on-failure** — every `tenant shell <name>`
  runs the full reapply BEFORE `Executor::login`. Unconditional
  (PF reload + every share op idempotent at substrate) and
  load-bearing (any failure aborts login). `ShellError { Account,
  Mode }`; dispatch routes Mode failures through
  `surface_shell_mode_error` — six arms framed as "before shell
  entry". Recovery on share failure: `tenant reload <name>`
  (idempotent) or address the `ShareError` refusal. `shell_intent`
  emits BEFORE the profile read so verb context shows even on
  profile-read failure. Negative pin: no `FlushAnchor` /
  `BackupConfig` / `RestoreConfigFromBackup` / `RemoveAnchor` ever
  fires on shell.

- **Auto-narrow only protects the `tenant shell` entry path** —
  `sudo -iu tenant` directly bypasses the binary and inherits the
  current anchor posture. If install-tier widening was left in
  place before reboot, pf.conf reloads the still-widened anchor on
  boot. `tenant shell <name>` is the canonical entry point.

- **Tenant-floor guard on destroy** — `destroy_eligibility` refuses
  with `EX_USAGE 64` when the named account exists with UID below
  `TENANT_UID_FLOOR` (`NotATenant`) or no positive UID
  (`SystemAccount`). Charset rail (`validate_name`) upstream, floor
  downstream. Both hard rails; `--force` override on roadmap.

- **Snapshot-then-act on the Reader** — `MacosReader::new()` queries
  dscl once at composition-root construction; subsequent lookups
  serve from the in-memory snapshot. Concurrent admin process
  mutating `/Users` between snapshot and `sudo sysadminctl …` could
  cause us to destroy an account whose UID changed; exploitation
  requires concurrent root, so we accept the TOCTOU window. Future
  daemon-mode mitigation: pass `-UID <verified>` to sysadminctl.

- **Composition-root DI** — `tenant::run` takes `&dyn
  accounts::Reader` + `&dyn executor::Executor`. `main.rs` builds
  prod impls; tests build `StubReader` + `StubExecutor` /
  `NeverExecutor`. Writer + Reporter constructed inside `run` from
  the active Executor; both swap to `DryRunExecutor` when
  `--dry-run`. Test seam stays at the Executor boundary.

- **Exit codes** — `0` success (including destroy's convergent
  noop, orphan-group convergence, doctor's default "findings are
  informational" contract); `64` (`EX_USAGE`) for user-input
  failure (validation, create-side conflict, all refusals); `74`
  (`EX_IOERR`) for substrate execution failure on every verb
  except shell. Shell propagates the child shell's exit code
  (clamped 0..=255). `1` is clap's default for parse errors and
  `ModeLevel` rejection. Doctor's `--strict` carves: `1` if max
  severity is warning, `2` if any critical; without `--strict`
  doctor exits `0` on a successful walk.

- **Probe-as-tenant subsumes ACL semantics at the kernel level** —
  doctor's filesystem-exposure detection invokes `sudo -n -u
  <tenant> /bin/test -<r|x> <path>` and treats the exit code as
  ground truth: 0 → `Allowed`, 1 → `Denied`, else `Unknown`. The
  kernel composes POSIX + ACLs + sandbox + TCC, so doctor doesn't
  need an `effective_access(...)` modeling macOS ACL semantics.
  Per-utility absolute paths are load-bearing on Darwin 25.x:
  `/bin/test`, `/bin/ln`, `/bin/mkdir`, but `/usr/bin/readlink`
  (`/usr/bin/test` and `/bin/readlink` are both absent on Darwin
  25.x). No single bin-directory is canonical; the answer is
  per-utility. `Denied` doesn't tell the operator WHY
  (POSIX vs ACL vs sandbox); parked for the remediation surface.
  Curated list collapses path-not-present into `Denied`; verbose
  block names every probed path so `no findings` is bounded to
  THIS LIST.

- **Doctor's curated-path list is bounded and operator-visible** —
  `curated_paths(host, tenant, others)` returns a fixed list; no
  operator-supplied path glob. Bounded scope is the contract: "no
  findings" must mean a known set. Verbose `doctor_starting`
  emits "Curated sensitive paths checked for tenant 'X':" + one
  indented `<verb> <path>` line per entry. Standard mode is
  silent. Future broadening to user-supplied targets must preserve
  list-it-out on verbose.

- **Doctor's host-wide findings emit once per invocation** —
  `EnvLeak` (Warning; `/etc/sudoers` + `/etc/sudoers.d/*`;
  hard-coded `SSH_AUTH_SOCK`; one-line sudoers edit to fix),
  `TouchIdMissing` (Info — Touch ID is a recommendation aligned
  with the locked NOPASSWD-sudoers stance, not correctness drift;
  doesn't trip `--strict`; `has_pam_tid` accepts only `auth
  sufficient pam_tid.so`), `PfDisabled` (Critical — only finding
  that says "your isolation guarantee is currently zero"; `pfctl
  -si`; recovery `sudo pfctl -e`). All three emit once at top of
  `doctor_tenant` / `doctor_all_tenants`. Inline pre-exec audit
  (`pre_exec_doctor_summary`) reuses the same posture.

- **Only unqualified `Defaults env_delete` counts as protection** —
  sudo's `Defaults` supports qualifiers (`Defaults:user`,
  `Defaults>runas`, `Defaults@host`, `Defaults!cmd`).
  `has_env_delete_for` accepts ONLY the unqualified form. A
  `Defaults>plugin-dev env_delete += "X"` applies only when sudo
  runs AS `plugin-dev` — does NOT protect `sudo -u <tenant>`.
  Negative pins for all four qualifier shapes in
  `tests/env_policy_parse.rs`. conservative-false; a
  qualified directive that genuinely covers the use case sees a
  false-positive; recovery is to add an unqualified `Defaults
  env_delete += "SSH_AUTH_SOCK"` to silence.

- **Doctor doesn't fit the WritableOp shape** — all doctor probes
  are Executor carve-out methods, NOT `Op<'a>` variants. Probes
  are how doctor LEARNS, not what the verb DOES — plan/echo
  dispatch would emit ~50 lines of `$ sudo -n -u tenant test
  -r ...` per tenant. No `Op::Doctor(_)` variant exists.

- **PF rule presence is structural, not exact-match** —
  `pf_rule_presence_check(rules, tenant)` looks for AT LEAST one
  line beginning with `pass ` and one with `block ` (after
  stripping leading whitespace, skipping comments). Returns up to
  two `PfRuleDrift` Warning findings. Exact line-by-line rejected:
  pfctl's output format isn't a stable contract (numerical IPs vs
  hostnames, table-reference reformatting, rule reordering).
  Structural presence catches "kernel anchor is empty or wrong"
  without false-positiving on cosmetic drift. Recovery: `tenant
  mode <name> runtime`.

- **Anchor-body drift is file-side, byte-exact, runtime-tier-only**
  — `Finding::AnchorBodyDrift` (Warning) complements the
  kernel-side `PfRuleDrift`: hand-edited on-disk file vs profile
  (here) vs in-kernel anchor diverged from file (PfRuleDrift's
  structural check). `read_anchor_body` reads
  `/etc/pf.anchors/tenant-<name>` (mode 0644; direct fs via
  `HostFileError`). `anchor_body_matches` is byte-exact vs
  `render_anchor(name, runtime_hosts)`; deterministic renderer ⇒
  any difference is real drift. RUNTIME tier only —
  install-tier widening outside an active shell session IS drift.
  profile read/parse failure SKIPS the check silently.
  Recovery: `tenant mode <name> runtime`.

- **HostFileError covers multiple host-config substrates** — shape
  (`Spawn` / `NonZero` / `Fs`) fits any privileged-or-cheap
  host-config-file read: sudoers + drop-ins (`read_env_policy`),
  pam.d/sudo (`read_pam_sudo`), on-disk anchor (`read_anchor_body`).
  Reuse rather than per-substrate error types. Reporter's
  `doctor_host_file_failed` frame is path-agnostic; the error's
  Display names the specific path / process detail.

- **Finding guidance is a 4-section block gated on `-v`** —
  `Finding::guidance(&self) -> Option<String>` returns flat text
  with sections Why this matters → Recommended fix → Side-effects
  → Alternative (column-0 headers, column-2 body). Standard mode
  emits the one-liner only; verbose prefixes each guidance line
  with 2 spaces. Style locks: sentence-case headers, imperative
  voice in fix justification, literal tenant name in per-tenant
  variants. Variants without a meaningful different command
  (TouchIdMissing, PfDisabled) omit Alternative. `FilesystemExposure`
  returns `None` (per-path guidance depends on file-vs-dir + intent
  + POSIX-vs-ACL fix; folds into the eventual remediation work).
  New `Finding` variants must author `guidance()` AND ship a
  per-variant byte-form pin in `tests/doctor.rs`.

- **Per-tenant `[[shares]]` are profile-driven, not CLI-driven** —
  filesystem-share substrate: profile TOML grows optional
  `[[shares]]`, each `(host_path, mode {ro|rw}, tenant_path)`.
  Source of truth is the profile; operator hand-edits + runs
  `tenant reload <name>`. Per-tenant. `host_path` literal absolute;
  `tenant_path` is a template with `$HOME` prefix-only resolution
  (position 0 only; mid-string refuses at parse). Mode `"ro"` /
  `"rw"` (POSIX bit-string forms rejected because file vs
  directory semantics diverge). Pre-flights BEFORE any substrate:
  `host_path.exists()` + `tenant_path_kind` reject
  `ShareError::HostPathMissing` / `TenantPathOccupied` — substrate
  NEVER clobbers operator data at a `tenant_path` that exists as
  a real file/dir. Removed entries are NOT auto-revoked; doctor
  surfaces orphans.

- **`AclOp` sub-domain — chmod-+a-natively-idempotent** —
  `AclOp::Grant { path, group, mode }` / `Revoke` map to `chmod
  +a/-a "group:<g> allow <bits>" <path>` (no sudo). `AclMode {
  Ro, Rw }` is the substrate sibling of `profile::ShareMode`. Bit
  lists ported from sandbox `acl.py`: ro =
  `read,execute,file_inherit,directory_inherit`; rw =
  `read,write,execute,delete,append,file_inherit,directory_inherit`.
  macOS chmod +a is NATIVELY idempotent. An earlier `ls -lde`
  substring-match pre-check was removed because macOS canonicalizes
  bit names on storage (`read,write,execute,delete,append` →
  `list,add_file,search,delete,add_subdirectory`), so it always
  false-negatived. `AclError { Spawn, NonZero }`. Revoke on absent
  entry surfaces `AclError::NonZero`; no path exercises Revoke
  today.

- **`EnsureDirAsUser` and `EnsureSymlinkAsUser` substrate-group
  with `LoginAsUser`** — three `AccountOp` variants share the
  `sudo -n -u <tenant> <cmd>` mechanism. Map to `mkdir -p` and
  `ln -sfn`. Both reuse `AccountError`. Grouping under `AccountOp`
  rather than `FilesystemAccessOp` is doctrinal: the shared
  mechanism (sudo-u) is what's shared. Writer skips
  `EnsureDirAsUser` when the tenant_path's parent IS the tenant
  home dir itself.

- **`tenant_path_kind` carve-out** — `sudo -n -u <tenant>
  /bin/test -L <path>` + `-e` collapse into `PathKind { Absent,
  Symlink(target: PathBuf), Other }`. `Symlink` carries the
  readlink target so `SymlinkDrift` can compare against the
  declared `host_path` in one substrate trip;
  `MacosExecutor::tenant_path_kind` calls `/usr/bin/readlink`
  after the `-L` hit and stores the raw target verbatim.
  Machinery failures: `ProbeError`. Used by
  `Writer::build_share_ops` to refuse `TenantPathOccupied` when
  kind is `Other`; `Symlink` is the idempotent re-link case.

- **`tenant reload [<name>]` — the "I edited config, apply it"
  verb** — single-tenant runs the full reapply at runtime tier; no
  tier-swap (use `tenant mode <name> install` for that). No-arg
  walks every tenant alphabetically; per-tenant failures don't
  abort — accumulates, surfaces one end-of-walk summary
  (`Reloaded N of M tenant(s); F failed.`). Exit 0 on clean walk,
  EX_IOERR (74) on any failure. Empty-host: "No tenants
  on this host to reload." `Verb::Reload { name: Option<String>
  }`; dispatch parallels `Doctor`'s no-arg form. Verb-name locked
  via `naming:naming-things` — `reload` won over `apply` /
  `refresh` / `reconcile` / `sync` / `converge`.

- **`Finding::AclDrift` + `Finding::SymlinkDrift` — per-tenant
  share-drift** — `Writer::check_share_drift` walks
  `parsed_profile.shares` and emits two independent findings per
  share: `AclDrift` when `read_host_acl(host_path)` doesn't carry
  the `<tenant>-tenant-share` group's `allow`; `SymlinkDrift` when
  `tenant_path_kind` returns a state mismatching the declared
  symlink. Both Warning; recovery `tenant reload <name>`. Bounded
  scope — paths from profile, not filesystem walking; orphan-ACL
  detection parked. Target comparison is string-exact (no
  `fs::canonicalize`). `NotSymlink` is a `SymlinkActual` case
  inside `SymlinkDrift`, NOT a separate variant — case-tailored
  guidance per variant (`tenant reload` recovers Absent +
  WrongTarget; manual cleanup first for NotSymlink, else
  `TenantPathOccupied` would fire). Per-share substrate failure
  aborts via `DoctorError::Probe`. `--fix` parked per the "tell,
  don't fix" doctrine.

- **`read_host_acl(path)` — operator-process `ls -lde`** —
  host-side ACL state from operator process (no
  sudo). Reuses `ProbeError`. Doctor parses via
  `has_group_acl_entry(listing, group) -> bool`, substring-matches
  `group:<g> allow`. Looser than full canonical entry — macOS
  canonicalizes bits on storage, so bit-list comparison would
  false-negative. Word-boundary discipline via ` allow` suffix
  prevents prefix-collision.

- **DryRun share-drift is structurally skipped, not synthesized**
  — `DryRunExecutor::read_profile` returns
  `default_profile_toml()` (no `[[shares]]`), so doctor's per-share
  loop never executes under production dry-run. Defensive returns
  on `DryRunExecutor::read_host_acl` / `tenant_path_kind` cover
  the future case where the default profile grows a share.

- **Host operator is a secondary member of every tenant's share
  group** — added at create via `AddHostToShareGroup` between
  `CreateShareGroup` and `CreateTenantUser`. Removed at destroy
  (and orphan-group convergence) via `RemoveHostFromShareGroup`;
  production substrate runs `dseditgroup -o checkmember` first
  and skips `-d` if absent. `Writer::execute_reapply_plan` re-adds
  at the top of the share substrate on every reload/mode/shell —
  catch-up for pre-existing tenants. Idempotent at substrate.
  `CreateError::HostMembership(AccountError)` hard-aborts with
  recovery hint pointing at `tenant destroy <name>`.
  `Finding::HostNotInShareGroup` (Warning) surfaces the drift via
  `Executor::host_in_group(host, group)`.

  *Known limitation:* macOS snapshots a process's supplementary
  group list at process creation, so the operator's CURRENT shell
  can't observe new membership — files the tenant creates inside
  RW shares fail with `Permission denied`. Workaround: open a NEW
  Terminal.app window. Permanent fix parked in
  `.features/roadmap.md` as "Host-direct ACL on share host_path".

- **Plan rendering pre-confirm, verbose-gated** — prompt-having
  verbs (`create` / `destroy` / `mode` / single-tenant `reload`)
  render the plan as a `Plan (commands to execute):` section
  INSIDE `*_summary`, verbose only — operator sees literal commands
  BEFORE `Proceed? [Y/n]`. Standard mode skips it; non-prompt verbs
  (`shell`, no-arg `reload`) keep plan in the verb. Scripted
  real-mode-verbose drops the plan (solo-Mac scope; `*_starting`
  divider + per-step `$` echo + ✓ progress is the trace surface).
  `*_starting` is section-only. Layout (`render_plan_block`): `  •
  <intent>[  # <annotation>]` + indented shell line beneath
  (six-space indent). Privilege-aware: first token `sudo` → bold +
  dim rest; else whole line dim. Bold-not-color keeps the severity
  color budget intact (red/green/yellow/cyan reserved for
  severity). Conditional annotations hang off the END of the
  intent line. Plan-build-pre-confirm: for mode / single-tenant
  reload, dispatch builds the plan via `Writer::build_reapply_plan`
  BEFORE the summary, so profile-read / share pre-flight failures
  surface pre-prompt; `apply_tenant_mode` / `reload_tenant` take a
  `&ReapplyPlan` parameter. No-arg `tenant reload` still builds
  per-tenant plans inside `reload_all_tenants`.

- **`Op::intent_label() -> String` — future-tense capability label**
  — sibling to `business_label()` (past-tense; drives ✓ progress).
  Used by `render_plan_block`. Sharpens weak `business_label` arms
  for probe variants (`LookupUserRecord`, `DeleteUserRecord`). New
  `Op` variants must author both at introduction.
  `tests/intent_labels.rs` pins per-variant byte form.

- **Pre-execution confirm: summary + Y/N + abort discipline** —
  every mutating verb on a TTY emits a pre-exec `*_summary` then
  prompts `Proceed? [Y/n]` (or `[y/N]` for destroy: only destroy
  is N-default — muscle-memory ENTER must not delete). Default-Y
  elsewhere (idempotent on re-run). Prompt loops on unrecognized
  input. Skip-conditions: dry-run (emits `(Real run would prompt:
  …)` preview), `--yes`, non-TTY stdin (preserves scripted-caller
  contract). On Abort: `Reporter::aborted()` + exit 0 without
  invoking substrate. Summary only emits when `cli.dry_run ||
  stdin_is_tty` — scripted real-mode callers stay silent.

- **Pre-exec doctor summary on mutating verbs** — each mutating
  verb runs a verb-relevant subset of doctor's checks between
  `*_summary` and confirm (`shell` before the section divider +
  login). Critical findings emit inline via
  `doctor_finding_one_liner` (colored one-liner; verbose guidance
  suppressed). Warning + Info count toward a single aggregate
  `⚠ Doctor: N warning(s) for tenant 'X' — run \`tenant doctor X\`
  for details` via `doctor_summary_pending` (no-tenant form drops
  scope clause for `create`). Healthy host: nothing. Per-verb
  relevance via `DoctorScope`: `create` → PfDisabled only; `shell`
  → PfDisabled + EnvLeak + all per-tenant drift; `mode` →
  PfDisabled + PF-side per-tenant drift (share drift is reload's
  job); `reload` → shell's per-tenant set + PfDisabled host-wide
  only (no EnvLeak). Substrate-machinery failures surface as
  `doctor_*_failed` stderr frames; function returns Ok — audit
  failure never aborts the verb (audit is a courtesy). Same
  `show_summary` gate as the summary.

- **`shell_summary` + clean-host stub default** — shell is the
  only mutating verb without a confirm prompt; the inline audit
  needs framing above it, so `shell_summary(name,
  host)` names firewall narrow, share reapply, login launch.
  `StubExecutor::tenant_path_kind` default returns
  `Symlink(host_path)` when the queried path matches a declared
  share's expanded tenant_path, else `Absent`; other audit
  substrate reads already had clean-host defaults. Net: a
  `StubExecutor::new()` with no explicit drift represents a
  doctor-passing host, so the pre-exec audit fires no findings on
  the existing test bank. Tests that exercise drift
  inject via `with_*_content` / `with_host_in_group` /
  `with_anchor_body` / `with_kernel_pf_rules` builders.

- **Per-stream ANSI gate threaded from main** — `ansi::Colors {
  stdout, stderr }` computed once at startup via `Colors::detect()`,
  threaded through `tenant::run` → `Reporter::new`. Reporter emits
  escapes only when the relevant stream's bit is true; tests pass
  `Colors::default()` (both false). NO_COLOR env deliberately not
  honored — solo-Mac scope. Pipe-to-cat / `2>err.log` works via
  per-stream `IsTerminal`.

- **Operator UX — section + ✓ + done** — real mode for every
  mutating verb brackets the substrate with `─── <verb> 'X' ───`
  + `✓ <business label>` per step + `─── Done ───` + a single
  enriched terminal line. ✓ lines come from `Writer::run<O>`
  calling `Reporter::progress(op)`, routing through
  `Op::business_label()` (past-tense, substrate-agnostic; no
  `dseditgroup` jargon). Dry-run skips section + ✓ + done;
  `*_summary` covers framing.

- **Doctor severity colors + verbose-guidance subordination** —
  `doctor_finding` colors severity per `Finding::severity()`:
  critical=red+bold, warning=yellow, info=dim. Verbose guidance
  block: bold on section headers (no leading whitespace), dim on
  body lines (indented). Color-off fallthrough is byte-form-
  identical to the surface.

- **Acronym casing** — Rust convention treats acronyms as words:
  `Uid` not `UID`, `Macos` not `MacOS`. Method `lowest_free_uid`,
  struct `UidAllocator`.

- **Clap flag scoping** — `-v / --verbose`, `--dry-run`, `-y /
  --yes` are `global = true` on `Cli`. Per-subcommand flags (e.g.
  `--strict`) stay scoped to their verb.

- **Comment density is a symptom, not a goal** — keep comments
  when WHY is non-obvious (hidden constraint, subtle invariant,
  bug-workaround, surprising behavior); drop when code/identifier
  says the same. Tracked source (`src/` + `tests/`) carries no
  cycle / Q-lock / SC references — a reader landing on the code
  in isolation should make sense of it. Tests follow the same
  rule, with one exception: sharpening / negative-pin comments
  survive (their WHY isn't carried by the test name). Module-level
  `//!` docs get a longer leash.

## Test discipline

E2E-first. Bulk of tests in `tests/cli_<verb>.rs` drive through
`tenant::run` with a `StubReader`; `tests/cli.rs` holds CLI-parser
cross-cutting. Shared helpers in `tests/common/mod.rs`. Inline
`#[cfg(test)] mod tests` is out of style; standalone unit-test
files need explicit justification — `tests/macos_executor.rs` and
`tests/macos_reader.rs` are precedents for per-substrate boundary
pins; the parse/render/classify pin files all carry the same:
combinatorial coverage on a pure function whose call sites are
inside the writer and would otherwise need many overlapping E2E
tests.

`run_with(stub, args) -> (u8, String, String)` wires a
`NeverExecutor` (panics on any substrate call). `run_with_exec(stub,
&StubExecutor, args)` lets the test own the executor for real-mode
assertions. Both run in-process.

Behavioral assertions: op identity (`exec.account_ops()`,
`profile_ops()`, `firewall_ops()`, `logins()`). Display assertions:
byte-exact. They pin the user-facing contract; cosmetic message
tweaks need test edits.

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
