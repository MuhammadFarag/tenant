# tenant — Rust port of the macOS tenant-account CLI

A small CLI for provisioning macOS user accounts, primary groups
(named `<name>-tenant-share`) in a project-reserved UID/GID range
(≥600), a per-tenant profile (TOML at
`~/.config/tenant/profiles/<name>.toml`), and a per-tenant PF anchor
(`/etc/pf.anchors/tenant-<name>`, referenced from `/etc/pf.conf`).

Verbs:
- `tenant create <name>` — provision user + share group + profile +
  PF anchor; enables pf.
- `tenant destroy <name>` — symmetric teardown; convergent (absent ⇒
  noop; orphan-group ⇒ converges); ends with `pfctl -a tenant-<name>
  -F all` to flush in-kernel rules.
- `tenant mode <name> install|runtime` — re-render anchor at the
  requested tier + reload pf.
- `tenant shell <name> [--mode install|runtime] [-- <cmd>]` — enter
  the tenant. Empty argv = interactive login; non-empty argv after
  `--` = single-command form. Auto-narrows + reapplies shares on
  entry; install-mode widens for the call and narrows back on
  completion. Child exit propagates; narrow-on-finally failure emits
  a `⚠` stderr warning without overriding the child's exit.
- `tenant reload [<name>]` — reapply profile to host state. No-arg
  walks every tenant; exits 0 / 74.
- `tenant doctor [<name>]` — read-only audit (paths, sudoers, pf,
  anchor, shares, group membership). `--strict` maps max severity to
  exit 1 / 2.

Rust port of an earlier Go prototype (at `/Users/plugin-dev/src/tenant/`
for cross-reference); follows Rust idioms (clap derive,
composition-root DI, trait-object HostUserDirectory) rather than mirroring the
Go shape.

## Scope

This file carries stable doctrine and a file map — facts about what
the code currently does and the non-obvious rules that govern its
shape. Per-cycle narrative lives in `.features/roadmap-shipped.md`;
commit chronology walks via `git log --oneline`. Don't grow this
file with shipped-feature recaps.

## File map

```
src/lib.rs        — public API: `run` entry + module tree + re-exports
                    of `Cli` / `Verb` / `ModeLevel` (from `cli`) and
                    `Terminal` (from `terminal`). `run` takes a parsed
                    `Cli` + `&dyn HostUserDirectory` + `&dyn HostMachine`
                    + `Terminal`; resolves operator identity, swaps to
                    `DryRunHostMachine` when `cli.dry_run`, hands off to
                    `commands::dispatch`.
src/cli.rs        — clap surface: `Cli` + `Verb` + `ModeLevel`; global
                    `--verbose` / `--dry-run` / `--yes`. Argv parsing
                    happens at the binary boundary (`Cli::parse()` in
                    `main`, `Cli::try_parse_from` in test helpers); re-
                    exported flat from the crate root.
src/terminal.rs   — `Terminal { stdout, stderr, stdin, stdin_is_tty,
                    colors }`: capability bundle for operator-side I/O,
                    constructed once at the binary boundary (main /
                    test helpers) and threaded as a single value through
                    `run` → `Reporter`.
src/ansi.rs       — `Colors { stdout, stderr }` per-stream gate; color
                    wrappers; `rule(title, width)` section divider.
src/domain/       — domain layer. `host_user_directory.rs` defines the
                    `HostUserDirectory` trait — driven port for account
                    inventory queries (`used_uids` / `used_gids` /
                    `has_user` / `has_group` / `uid_for` /
                    `tenant_names`). `host_machine.rs` defines the
                    `HostMachine` trait — driven port for the host-side
                    substrate (per-domain `describe_*` / `execute_*`
                    pairs + non-unit carve-outs: `login`,
                    `exec_as_tenant`, `read_profile`, `read_pf_conf`,
                    `probe_access_as_tenant`, `read_env_policy`,
                    `read_kernel_pf_rules`, `read_pam_sudo`,
                    `read_pf_status`, `read_anchor_body`,
                    `read_host_acl`, `tenant_path_kind`,
                    `host_path_kind`, `host_in_group`) plus the
                    `WritableOp` bridge trait. `ops.rs` carries the
                    `Op` ADT over `AccountOp` / `ProfileOp` / `FirewallOp` /
                    `AclOp` plus the four `impl WritableOp for *Op`
                    blocks. `errors.rs` carries the per-domain error
                    types (`AccountError`, `UserDirectoryError`, `AclError`,
                    `FirewallError`, `HostFileError`, `ProbeError`).
                    `ids.rs` carries the domain newtypes (`UserId` / `GroupId` /
                    `TenantUserName` / `HostUserName` / `GroupName`),
                    re-exported flat from `crate::domain`.
src/domain/tenants.rs / tenants/
                  — facade: `Tenants` struct + `new()` + the generic
                    `run<O: WritableOp>` narrate-execute-narrate
                    dispatcher + `tenant_share_group_name` +
                    `cowork_dir_path` + `guard_cowork_dir_kind`. Each
                    per-verb submodule owns its complete code (error
                    type + `impl Tenants` block + bound helpers /
                    data carriers) via split impl blocks across
                    files: `validation.rs` (`NameError`,
                    `ConflictError`, `validate_name`,
                    `check_conflict`), `create.rs` (`CreateError`,
                    `create`), `destroy.rs` (`DestroyError`,
                    `Eligibility`, `destroy_eligibility`, `destroy`,
                    `destroy_orphan_group`), `reapply.rs`
                    (`ModeError`, `ReapplyPlan`, `ReloadAllOutcome`,
                    `hosts_for_level`, `mode`, `build_reapply_plan`,
                    `execute_reapply_plan`, `reload`, `reload_all`),
                    `shares.rs` (`ShareError`, `ShareOps`,
                    `build_share_ops`, `execute_share_ops`,
                    `reapply_shares_post_provision`), `shell.rs`
                    (`ShellError`, `shell` branching on argv-presence
                    into `shell_interactive` / `shell_command`),
                    `doctor.rs` (`DoctorError`, `DoctorScope`,
                    `DoctorOutcome`, the eight probe methods, plus
                    `doctor`, `doctor_all`, `pre_exec_doctor_summary`).
                    Error types re-exported from the facade.
src/domain/commands.rs
                  — verb dispatch (no I/O). Per-arm `surface_*_error`
                    helpers route domain errors to Reporter. Dispatch
                    builds `ReapplyPlan` upfront for prompt-bearing
                    verbs so profile-read failures surface pre-prompt.
src/domain/reporter.rs
                  — operator-facing output. Owns the `Terminal`
                    capability by value (single field; method bodies
                    access `self.terminal.stdout` etc.). `section` +
                    `ok` (✓) + `step` ($-echo) + `progress` substrate
                    vocab. Per-verb `_intent` / `_summary` / `_done`
                    triples; `_summary` carries optional `Plan (commands
                    to execute):` block in verbose. `confirm()` +
                    `aborted()` + `show_summary()` (truth table
                    `dry_run || stdin_is_tty`). `doctor_finding` /
                    `doctor_finding_one_liner` /
                    `doctor_summary_pending` drive the audit surface.
src/adapters/     — driven adapters. `macos/user_directory.rs`
                    (`MacosUserDirectory` — ZST driver; per-call dscl
                    with `eDSRecordNotFound` absence detection;
                    symmetric with `MacosHostMachine`).
                    Two `HostMachine` impls: `macos/host_machine.rs`
                    (`MacosHostMachine` — production substrate; owns
                    argv for dseditgroup / sysadminctl / dscl / pfctl
                    / chmod, tempfile-based privileged writes, the
                    XDG-style profile path),
                    `dry_run_host_machine.rs` (`DryRunHostMachine` — no-op
                    execute; describe delegates to `MacosHostMachine`;
                    read carve-outs return "no actionable warning"
                    placeholders).
src/allocation.rs — `UidAllocator` + `GidAllocator`. Independent; both
                    iterate from `TENANT_UID_FLOOR = 600`.
src/profile.rs    — TOML serde shapes + `parse` (schema-version +
                    `$HOME` prefix-only validation); `expand_tenant_path`;
                    `default_profile_toml`.
src/firewall.rs   — pure: `render_anchor`, `ensure_anchor_ref`,
                    `remove_anchor_ref`, `is_anchor_referenced`;
                    `tenant_anchor_name` / `_path`.
src/doctor.rs     — pure grep-and-classify. `Finding` + `Severity` +
                    `Category` + `SymlinkActual` shapes; the parse +
                    classify functions. All I/O lives in `Tenants::doctor_*`.
src/main.rs       — composition root: prod impls + `tenant::run`.
                    Reads `$USER`; probes stdin TTY + colors; builds
                    `Terminal` over real stdout/stderr/stdin.

tests/cli_*.rs            — E2E, one binary per verb plus `cli.rs`
                            for parser cross-cutting. Each declares
                            `mod adapters; mod common;` (adapters first
                            so common can reach `crate::adapters`).
tests/common/mod.rs       — output/plan builders, test runners
                            (`run_with`, `run_with_exec`,
                            `run_with_stdin`), stub-factory helpers
                            (`stub_with_tenant`, `make_tenant_stub_reader`,
                            `make_two_tenant_stub_reader`,
                            `profile_with_hosts`, `profile_with_shares`,
                            dry-run block helpers). `TEST_HOST` constant.
tests/adapters/           — test-only adapter impls:
                            `StubHostMachine` (records every op
                            invocation; per-op failure injection +
                            builder-pattern preload of profile / pf-conf
                            / env-policy / anchor-body / probe-outcome
                            state), `StubUserDirectory` (HashMap-backed
                            inventory with per-method
                            `RefCell<VecDeque<Option<UserDirectoryError>>>`
                            failure-injection queues),
                            `NeverHostMachine` (panicking `HostMachine`
                            impl; default for `run_with` so paths that
                            should not reach the substrate fail loudly).
                            All accessible via `use adapters::*;`.
tests/macos_host_machine.rs
                          — per-variant pins of
                            `MacosHostMachine::describe_*` argv contracts.
tests/intent_labels.rs    — per-variant pins of `Op::intent_label()`
                            + sharpening pins (intent ≠ business label).
tests/macos_user_directory.rs
                          — `MacosUserDirectory` per-call dscl smoke +
                            `eDSRecordNotFound` absence-detection pin
                            (`#[cfg(target_os = "macos")]`).
tests/doctor.rs           — combinatorial: classify matrix, `Finding`
                            display, guidance, severity ordering.
tests/{env_policy,pf_rule,pam,host_acl,profile,firewall_render,firewall_conf}_parse.rs
                          — combinatorial on the pure functions in
                            `src/doctor.rs` / `src/firewall.rs`.
```

## Project doctrine

Rules that an LLM reading the source cold could plausibly violate.
Each rule encodes a decision that has already been made — re-deriving
it from scratch wastes a cycle and risks getting it wrong.

### ADT + trait shape

- **Intent / mechanism split.** Domain ops (`AccountOp` / `ProfileOp`
  / `FirewallOp` / `AclOp`) express *what*; `MacosHostMachine` owns argv.
  Tenants never constructs argv. Tests assert on op identity (e.g.
  `exec.account_ops()[N] == AccountOp::CreateShareGroup{..}`); literal
  shell shape pinned narrowly in `tests/macos_host_machine.rs`, one test
  per variant.

- **One `HostMachine` trait; sub-domains live as method-pairs.** Adding
  a future sub-domain extends `HostMachine` with a new `describe_*` /
  `execute_*` pair plus a leaf `Op<'_>` variant — no new trait. The
  single `HostMachine` is the one test seam at the host boundary,
  preserving per-domain error types end-to-end.

- **Carve-out methods for non-unit returns.** HostMachine methods that
  don't fit `Result<(), E>` are called directly by Tenants: `login` /
  `exec_as_tenant` (stdio inherit, i32 child exit), content reads
  (return `String`), probe verdicts (return enum / bool).
  `AccountOp::LoginAsUser` + `ExecAsUser` exist only for plan/echo
  render — `execute_account` panics on them. Future HostMachine method:
  if it fits `Result<(), E>`, make it an ADT variant; if not, carve out.

- **Probe via HostMachine, not HostUserDirectory re-read.** When a verb
  needs to re-check OS state mid-execution (destroy's
  `LookupUserRecord` residue probe is canonical), it's a regular
  substrate call whose `Ok` vs `Err` drives a Tenants branch.
  HostUserDirectory is for inventory queries (presence, IDs, enumeration)
  consumed up front in dispatch; per-mutation follow-up probes
  belong on HostMachine alongside the mutation they verify.

- **Host-side vs tenant-side path probes.** Two carve-outs answer
  "what's at this path?": `tenant_path_kind` probes via `sudo -n -u
  <tenant>` — used for paths whose accessibility depends on the
  tenant's perspective (declared share `tenant_path`s);
  `host_path_kind` probes via host filesystem directly (no sudo) —
  used for paths the host owns by design (cowork dirs). Pick by
  ownership semantics, not by what's already wired: the tenant-side
  probe doesn't work when the tenant user is absent (orphan-group
  destroy, post-`DeleteTenantUser` tail steps), so a host-owned
  path's check must use `host_path_kind` to work uniformly.

- **Doctor doesn't fit the `WritableOp` shape.** All doctor probes
  are HostMachine carve-out methods, NOT `Op<'a>` variants. Probes are
  how doctor LEARNS, not what the verb DOES — plan/echo dispatch
  would emit ~50 lines of `$ sudo -n -u tenant test -r ...` per
  tenant. No `Op::Doctor(_)` variant.

- **`HostFileError` covers multiple host-config substrates** —
  sudoers + drop-ins (`read_env_policy`), pam.d/sudo
  (`read_pam_sudo`), on-disk anchor (`read_anchor_body`). Reuse
  rather than per-substrate error types. Reporter's
  `doctor_host_file_failed` frame is path-agnostic; the error's
  Display names the specific path.

- **`AccountOp::LoginAsUser` / `ExecAsUser` / `EnsureDirAsUser` /
  `EnsureSymlinkAsUser` substrate-group under `sudo -[in] -u <tenant>`.**
  The shared mechanism is what's shared; grouping under `AccountOp`
  is doctrinal. `LoginAsUser` + `ExecAsUser` carve out to
  `HostMachine::login` / `exec_as_tenant` (stdio inherit + i32 child
  exit); the other two flow through `execute_account`.

### Layering + DI

- **No I/O in command logic.** `commands::dispatch` and
  `tenants::Tenants` call Reporter's verb-named methods; neither
  touches raw writers nor checks `cli.verbose` / `cli.dry_run`. Mode
  / verbosity branching lives inside Reporter.

- **Composition-root DI.** `tenant::run` takes a parsed `Cli` + `&dyn
  HostUserDirectory` + `&dyn host_machine::HostMachine` + a `Terminal`
  bundle. Argv parsing lives at the binary boundary: `main.rs` uses
  `Cli::parse()` (clap exits the process on `--help` / `--version` /
  bad input), test helpers use `Cli::try_parse_from` and route clap's
  rendered errors to the captured stdout/stderr per `use_stderr()`. Prod
  impls live in `main.rs`; tests build `StubUserDirectory` +
  `StubHostMachine` / `NeverHostMachine`. Tenants + Reporter constructed
  inside `run` from the active HostMachine; both swap to
  `DryRunHostMachine` when `cli.dry_run`. Test seam stays at the
  HostMachine boundary.

- **Adapters live under `.../adapters/`, regardless of src vs tests.**
  Production-reachable adapters (`MacosHostMachine`, `MacosUserDirectory`,
  `DryRunHostMachine`) stay in `src/adapters/`. Test-only adapter impls
  (`StubHostMachine`, `StubUserDirectory`, `NeverHostMachine`) live in
  `tests/adapters/`, accessed via `use adapters::*;` after `mod adapters;`.
  Keeps the production library surface free of `RefCell`-laden test
  scaffolding; mirrors the src structure for discoverability.

- **Terminal is the capability, not a bundle.** All operator-side I/O
  (stdout / stderr / stdin / stdin_is_tty / colors) is carried by the
  `Terminal` struct, threaded as a single value through `run` → `parse`
  → `Reporter`. Reporter owns it by value; method bodies access
  `self.terminal.stdout` etc. — never unpacked into separate Reporter
  fields. Any future function that needs operator I/O takes `Terminal`
  (or `&mut Terminal`) as a whole, even if it only writes to one field
  — the type names "I have operator-I/O authority," not "I have these
  three specific handles." Don't carve out `fn h(stderr: &mut dyn
  Write)` shapes; pass `Terminal` and let the body access what it
  needs.

- **Per-call dscl on `HostUserDirectory`.** `MacosUserDirectory` is a ZST;
  each trait method spawns dscl per call. No internal cache, no eager
  snapshot at composition-root. A verb that calls `has_user` +
  `uid_for` + the allocator pays N+1 dscl spawns; on a solo-Mac admin
  CLI this latency is invisible. Absence is detected by the
  `eDSRecordNotFound` stderr signal, not by treating any nonzero as
  absent — preserves the conflict-probe / eligibility frames' contract
  when dscl itself breaks (permissions, daemon hung). The TOCTOU
  window between query and mutation is "lookup → next syscall" rather
  than "composition root → minutes later"; still nonzero but no
  longer doctrine-worthy.

### Verb semantics

- **Lexical → state-based check order.** `validate_name` (charset)
  runs before `check_conflict` / `destroy_eligibility` (OS state).
  Cheaper failure first.

- **Convergent semantics for teardown verbs.** `destroy <name>`
  against an absent tenant is a successful noop. Absent user +
  leftover `<name>-tenant-share` group routes to
  `Tenants::destroy_orphan_group`. Orphan path runs the full PF
  teardown (each step idempotent), so partial-firewall state from a
  failed earlier create also converges.

- **Centralized name builders.** `tenants::tenant_share_group_name(name)`
  for the group suffix; `firewall::tenant_anchor_name(name)` /
  `tenant_anchor_path(name)` for the anchor. Don't inline `format!`
  at call sites.

- **Decoupled UID/GID allocation.** `UidAllocator` reads `used_uids`;
  `GidAllocator` reads `used_gids`. The two spaces are disjoint and
  may legitimately diverge (UID 613, GID 600). Don't fuse them.

- **Tenant-floor guard on destroy.** `destroy_eligibility` refuses
  with `EX_USAGE 64` when the named account exists with UID below
  `TENANT_UID_FLOOR` (`NotATenant`) or no positive UID
  (`SystemAccount`). Charset rail upstream, floor downstream. Both
  hard rails.

- **Exit codes.** `0` success (including destroy convergent-noop,
  orphan-group convergence, doctor's default informational contract).
  `64` (`EX_USAGE`) for user-input failure (validation, conflicts,
  refusals). `74` (`EX_IOERR`) for substrate execution failure on
  every verb except shell. Shell propagates the child's exit code
  (clamped 0..=255); command form's narrow-on-finally failure does
  NOT override the child's exit (warning carries the firewall
  signal). `1` is clap's default for parse errors and `ModeLevel`
  rejection. Doctor's `--strict` carves: `1` if max severity is
  warning, `2` if any critical; without `--strict`, doctor exits `0`.

### Create + teardown

- **Create partial-failure recovery posture.**
  `CreateError::UserWithRollback` emits two Reporter calls (original
  error + em-dash-suffixed rollback-failed hint). Profile/Firewall
  failures leave user + group on host; recovery is `tenant destroy
  <name>` (idempotent on PF). On PF Reload failure, Tenants runs an
  automatic 4-step recovery (RestoreConfigFromBackup → RemoveAnchor
  → Reload → FlushAnchor) BEFORE surfacing the error; recovery-of-
  recovery surfaces as `FirewallError::RestoreFailed { path }` with a
  manual-recovery hint. `PostProvision(ModeError)` recovers via
  `tenant reload <name>`, NOT another `tenant create` (would refuse
  on name-conflict).

- **`KeychainOp::CreateLoginKeychain` is idempotent against duplicate
  keychain.** The first of the 4 `security` calls
  (`create-keychain`) exits non-zero with stderr "already exists" if
  the tenant's `login.keychain-db` already exists on disk (retry
  after a partial create, or any re-attached `/Users/Deleted Users/`
  home). The substrate adapter swallows that one error as `Ok(())`
  and re-applies the remaining three calls (`default-keychain -s`,
  `list-keychains -s`, `set-keychain-settings`), which are natively
  idempotent. Same posture as `pfctl -e "already enabled"` and
  `chmod +a` ACL grants. Detection is on the stderr substring
  (case-insensitive), not on a specific exit code — macOS shifts the
  code across versions. The other 3 calls are not pre-guarded; if
  they fail, partial state (just the keychain file) remains and is
  cleaned transitively by `tenant destroy` moving the home to
  `/Users/Deleted Users/`.

- **`tenant shell` unlocks the tenant's login keychain before exec.**
  Shared pre-spawn step on both `shell_interactive` and `shell_command`
  paths (after `execute_reapply_plan`, before `HostMachine::login` /
  `exec_as_tenant`): `find_stashed_password` retrieves the operator-
  keychain stash via `security find-generic-password -a <name> -s
  tenant-<name> -w`, then `unlock_tenant_keychain` runs `sudo -iu
  <name> security unlock-keychain -p <pw> login.keychain-db`. Both
  are HostMachine carve-outs (non-unit returns; no `KeychainOp`
  variant — the unlock pass is mechanism, not a planned op).
  `KeychainPassword::from_existing(String)` is the `pub(crate)`
  constructor for substrate-retrieved passwords; only the macOS
  adapter reaches it. `KeychainError::NotFound` → `ShellError::
  StashAbsent` → `EX_USAGE` (64) with a refusal frame naming
  `tenant destroy <name> && tenant create <name>` verbatim (legacy-
  tenant migration); any other `KeychainError` → `ShellError::
  UnlockFailed` → `EX_IOERR` (74). Already-unlocked is a successful
  no-op on the substrate side; no idempotence guard in our code. No
  `Finding::TenantKeychainLocked` doctor probe — `security show-
  keychain-info` via `sudo -iu` triggers SecurityAgent on Darwin
  25.x, ruling out any non-interactive state probe; sandbox prior
  art converged on the same unconditional-unlock-at-shell-entry
  architecture.

- **PF anchor flush is load-bearing on destroy paths.** `pfctl -f
  /etc/pf.conf` does NOT garbage-collect anchors whose `load anchor`
  directive has been removed. Without `pfctl -a tenant-<name> -F all`,
  the previous tenant's rules persist in kernel memory under an
  orphan name; the next tenant getting the same UID silently
  inherits them. `FirewallOp::FlushAnchor` is the final step on both
  destroy paths and on create-side reload-failure recovery. Negative
  pin: create's success path and the reapply paths (mode/shell/reload)
  do NOT invoke FlushAnchor — they leave the parent `load anchor`
  directive in place, so `pfctl -f` re-reads it.

### Reapply (mode / shell / reload)

- **Mode/shell/reload share `build_reapply_plan` +
  `execute_reapply_plan`.** All three reapply the profile (PF anchor
  at requested tier + per-share `AclOp::Grant` + optional
  `EnsureDirAsUser` + `EnsureSymlinkAsUser`). Build is separated from
  execute so dispatch can render the upfront plan and surface
  profile-read failures pre-prompt. Share pass runs AFTER PF reapply
  lands so a Reload failure aborts before any ACL/symlink mutation.
  `execute_share_ops` is shared with `reapply_shares_post_provision`
  (create's post-Enable share pass; skips PF).

- **`tenant shell` collapses interactive + command forms.** Argv
  presence is the discriminator. Prior-art lock: kubectl / docker /
  ssh / sudo / runuser all unify both forms under one verb. Clap
  `last = true` on `argv` requires the `--` separator; `requires =
  "argv"` on `--mode` rejects bare `tenant shell <name> --mode
  install` at parse (widening the interactive session would either
  need narrow-on-exit machinery or leave install-tier widening
  silent). No confirm prompt on either form.

- **Command-form narrow-on-finally is gated on `mode == Install`.**
  Runtime-mode entry IS the runtime posture; a second post-child
  reapply would write the same bytes for zero on-disk delta — skip.
  Install-mode entry widens; the post-child runtime-tier reapply is
  mandatory regardless of child outcome. Widen-build failure (no
  substrate fired) skips the narrow; widen-execute failure runs a
  best-effort inline narrow before the Mode error surfaces. Child
  exit code propagates per option (a); narrow-failure emits a `⚠`
  stderr warning but does NOT override the child's exit.
  `ShellError::NarrowFailed { child_exit, narrow_err }` carries
  both; interactive form never exercises that arm.

- **Auto-narrow protects only the `tenant shell` entry path.** `sudo
  -iu tenant` directly bypasses the binary and inherits the current
  anchor posture. `tenant shell <name>` is the canonical entry point.

### Shares

- **Per-tenant `[[shares]]` are profile-driven, not CLI-driven.** Each
  entry is `(host_path, mode {ro|rw}, tenant_path)`. `host_path` is
  literal absolute; `tenant_path` is a template with `$HOME` prefix-
  only resolution (position 0 only; mid-string refuses at parse).
  Mode `"ro"` / `"rw"` only (POSIX bit-string forms rejected because
  file-vs-directory semantics diverge). Pre-flights BEFORE any
  substrate: `host_path.exists()` + `tenant_path_kind` reject
  `ShareError::HostPathMissing` / `TenantPathOccupied`. Removed
  entries are NOT auto-revoked; doctor surfaces orphans.

- **`AclOp::Grant` / `Revoke` are chmod-+a-natively-idempotent.** Grant
  maps to `chmod -R +a "group:<g> allow <bits>" <path>`; Revoke maps
  to `chmod -a "group:<g> allow <bits>" <path>` (no sudo, no `-R`).
  Bit lists: ro = `read,execute,file_inherit,directory_inherit`; rw =
  `read,write,execute,delete,append,file_inherit,directory_inherit`.
  macOS chmod +a is natively idempotent; no substring-match pre-check
  (macOS canonicalizes bit names on storage, so `read,write,execute`
  → `list,add_file,search`, defeating exact-match comparison).
  Grant recurses so shares declared on already-populated host
  directories reach existing children; `file_inherit,directory_inherit`
  only cover future children. Revoke stays single-pass: `chmod -R -a`
  fails on any tree node missing the ACE (cp doesn't preserve macOS
  ACLs), and top-level revoke is sufficient — inherited child ACEs
  become orphan-inert once the share group is removed downstream in
  the destroy sequence.

- **`chmod -R +a` adds the ACE as a direct entry on every visited
  node, even when the node already carries the same ACE as an
  inherited entry** (macOS chmod doesn't deduplicate across the
  direct-vs-inherited boundary). Files that existed at apply time
  and previously picked up the ACE via `file_inherit` end up with
  two `ls -le` entries after the next recursive grant: one direct,
  one inherited. chmod +a stays idempotent against direct
  duplicates, so subsequent reapplies don't accumulate further —
  the cruft is a one-time +1 per such file, bounded and
  functionally inert (both entries grant the same bits to the same
  group). Not worth a strip-and-regrant pass: `chmod -R -a` would
  fail on any node missing the ACE (same asymmetry that keeps
  Revoke single-pass).

- **`tenant_path_kind` returns `PathKind { Absent, Symlink(target),
  Dir, Other }`.** `Dir` distinguishes a real directory from `Other`
  (regular file, fifo, socket, etc.) so the cowork-dir pre-flight
  can accept an existing dir (mkdir-p no-ops) while refusing `Other`.
  Shares' `build_share_ops` refuses both `Dir` and `Other` as
  `TenantPathOccupied` — for a tenant-side symlink, a real file and
  a real dir are equally blocking. `Symlink` is the idempotent
  re-link case. Target stored verbatim from readlink so `SymlinkDrift`
  can compare against declared `host_path` in one substrate trip.

- **Host operator is a secondary member of every tenant's share
  group.** Added at create via `AddHostToShareGroup` between
  `CreateShareGroup` and `CreateTenantUser`. Removed at destroy via
  `RemoveHostFromShareGroup` (production substrate runs
  `dseditgroup -o checkmember` first and skips `-d` if absent).
  `execute_reapply_plan` re-adds on every reload/mode/shell as a
  catch-up for pre-existing tenants. *Known limitation:* macOS
  snapshots a process's supplementary group list at process creation,
  so the operator's CURRENT shell can't observe new membership until
  a new Terminal window opens.

#### Co-working dirs

- **Per-tenant co-working directory at `/Users/Shared/tenants/<name>`.**
  Owner is the host operator, primary group is
  `<name>-tenant-share`, mode `2770` (setgid + group-rwx + zero-other),
  with an inheritable rw ACL grant on the directory itself. ACL bits
  match a rw `[[shares]]` entry exactly:
  `read,write,execute,delete,append,file_inherit,directory_inherit`.
  Setgid propagates the share group to children at creation time;
  the inheritable ACL propagates the rw bits — together they make
  files created inside the dir collaboratively reachable by both
  the tenant and the host through the share group, without requiring
  a tenant umask change.

- **Cowork dirs are CREATED by tenant, not granted on pre-existing
  content.** Inverse posture to `[[shares]]`, which grant the share
  group an ACL on a host-owned path that already exists. The cowork
  dir's mode + ACL are tenant-managed end-to-end; the substrate
  `mkdir`s the path, `chown`s it, applies the mode, and grants the
  inheritable ACL.

- **`AccountOp::EnsureCoworkDir` is one variant, four substrate
  calls.** `mkdir -p` → `chown <host>:<share-group>` → `chmod 2770`
  → `chmod -R +a` with the rw bits. Each call is natively idempotent
  on macOS: `mkdir -p` no-ops on an existing dir, `chown` / `chmod`
  are state-setters, and `chmod -R +a` follows the rw-share Grant
  posture. `describe_account` returns a `\n`-separated multi-line
  string and `Reporter::step` / `render_plan_block` emit one
  privilege-aware line per substrate call.

- **Same op fires at create AND at every reapply.** `Tenants::create`
  inserts `EnsureCoworkDir` between `CreateTenantUser` and the
  keychain bootstrap; `build_reapply_plan` inserts it between
  `AddHostToShareGroup` and the per-share grants. The recursive ACL
  pass at every reapply heals drift and picks up tenant-added
  subdirectories between cycles. Failures during create surface via
  `CreateError::CoworkDir` at `EX_IOERR`; recovery is
  `tenant destroy <name>` (same posture as
  `Profile` / `Firewall` / `KeychainProvision`).

- **Path builder lives at the Tenants boundary.**
  `tenants::cowork_dir_path(name: &str) -> PathBuf` returns
  `/Users/Shared/tenants/<name>`; centralized so dispatch and the
  Tenants per-verb files share one source. Like
  `tenant_share_group_name`, it takes `&str` (the newtype
  `TenantUserName` lifts at the ADT variant boundary, not the
  builder).

- **Cowork-path kind-check fires on BOTH create AND every reapply.**
  `mkdir -p` errors on a regular file at the path and silently
  follows a symlink, leaving the subsequent chown + chmod pass
  mutating the link's target. `Tenants::create` and
  `build_reapply_plan` (reload / mode / shell) both probe the path
  before constructing `EnsureCoworkDir`: `Absent` and `Dir` continue,
  `Symlink(_)` and `Other` refuse with
  `AccountError::CoworkDirOccupied { path, kind }` — flowing through
  `CreateError::CoworkDir` on create and `ModeError::Account` on
  reapply. Probe failure rides the existing `AccountError::Spawn` /
  `NonZero` shape via a small adapter; no new error type. The
  shared helper lives in `src/domain/tenants.rs` as
  `guard_cowork_dir_kind` alongside `cowork_dir_path`. The check
  exists to prevent the substrate from following a symlink at the
  cowork path — that's a state-machine concern (corrupt prior op,
  hand-edit, leftover between sessions), not a race window.

- **`tenant destroy <name>` does NOT remove the cowork dir.** The
  dir holds operator-authored work; auto-deleting it is the failure
  mode we're avoiding. Both destroy paths (`Tenants::destroy` and
  `Tenants::destroy_orphan_group`) emit a one-line stdout notice at
  the tail of the success surface — between the last `✓` and the
  `─── Done ───` divider — naming the tenant and the intact path so
  the operator knows what was left behind across back-to-back
  destroys. The notice probes via `HostMachine::host_path_kind`
  (host-side, no sudo) — works uniformly across both destroy paths
  regardless of whether the tenant user is still resolvable.
  Convergent: probe returns `Absent` → no notice; probe returns
  `Dir | Symlink(_) | Other` → notice fires; probe error → yellow
  `⚠` stderr warning naming the path (same posture as the pre-exec
  doctor pass — courtesy surface, never an abort gate) and destroy
  continues. Distinct from `tenant_path_kind` by design: the cowork
  dir is host-owned, so probing through the tenant's identity would
  break on the orphan-group path (tenant absent by definition) and
  on the post-`DeleteTenantUser` tail of the full path.

### Doctor

- **Probe-as-tenant subsumes ACL semantics at the kernel level.**
  Doctor's filesystem-exposure detection invokes `sudo -n -u
  <tenant> /bin/test -<r|x> <path>` and treats the exit code as
  ground truth (0 → Allowed, 1 → Denied, else Unknown). The kernel
  composes POSIX + ACLs + sandbox + TCC, so doctor doesn't need an
  effective-access model. Per-utility absolute paths are load-bearing
  on Darwin 25.x: `/bin/test`, `/bin/ln`, `/bin/mkdir`,
  `/usr/bin/readlink` (`/usr/bin/test` and `/bin/readlink` are both
  absent). `Denied` doesn't say WHY (POSIX vs ACL vs sandbox); that's
  the remediation surface's job.

- **`DoctorScope::Shell` covers both shell forms** (no
  `DoctorScope::Exec` variant). Interactive and command forms share
  the audit-relevance set: `PfDisabled` host-wide + `EnvLeak`
  host-wide + all per-tenant drift.

- **Only unqualified `Defaults env_delete` counts as protection.**
  Sudo's `Defaults` supports qualifiers (`Defaults:user`,
  `Defaults>runas`, `Defaults@host`, `Defaults!cmd`). `has_env_delete_for`
  accepts ONLY the unqualified form. A qualified directive that
  genuinely covers the use case sees a false-positive; recovery is to
  add an unqualified `Defaults env_delete += "SSH_AUTH_SOCK"`.

- **PF rule presence is structural, not exact-match.**
  `pf_rule_presence_check(rules, tenant)` looks for AT LEAST one
  line beginning with `pass ` and one with `block ` (whitespace
  stripped, comments skipped). pfctl's output format isn't a stable
  contract (numerical IPs vs hostnames, table reformatting, rule
  reordering); structural presence catches "kernel anchor empty or
  wrong" without false-positiving on cosmetic drift.

- **Anchor-body drift is file-side, byte-exact, runtime-tier-only.**
  Complement to kernel-side `PfRuleDrift`: hand-edited on-disk file
  vs profile. `anchor_body_matches` is byte-exact vs
  `render_anchor(name, runtime_hosts)`; deterministic renderer ⇒ any
  difference is real drift. RUNTIME tier only — install-tier widening
  outside an active shell session IS drift. Profile read/parse
  failure SKIPS the check silently.

- **`Finding::guidance(&self) -> Option<String>` is a 4-section block
  gated on `-v`.** Sections: Why this matters / Recommended fix /
  Side-effects / Alternative. Sentence-case headers; imperative voice
  in the fix; literal tenant name in per-tenant variants. Variants
  without a meaningfully different command (`TouchIdMissing`,
  `PfDisabled`) omit Alternative. `FilesystemExposure` returns `None`
  (per-path guidance depends on file-vs-dir + intent + POSIX-vs-ACL
  fix). New `Finding` variants must author `guidance()` AND ship a
  per-variant byte-form pin in `tests/doctor.rs`.

- **Pre-exec doctor summary on mutating verbs.** Each mutating verb
  runs a verb-relevant subset of doctor's checks between `*_summary`
  and confirm. Critical findings emit inline via
  `doctor_finding_one_liner`; Warning + Info aggregate into a single
  `⚠ Doctor: N warning(s) … run \`tenant doctor X\` for details`
  via `doctor_summary_pending`. Healthy host: nothing. Substrate-
  machinery failures surface as `doctor_*_failed` stderr frames and
  the verb proceeds — audit is a courtesy, never an abort gate.

### Operator UX + plan rendering

- **Plan rendering pre-confirm, verbose-gated.** Prompt-having verbs
  (`create` / `destroy` / `mode` / single-tenant `reload`) render
  the plan as a `Plan (commands to execute):` section INSIDE
  `*_summary`, verbose only. Standard mode skips it; non-prompt verbs
  (`shell`, no-arg `reload`) keep plan in the verb. Layout: `  •
  <intent>[  # <annotation>]` + indented shell line beneath
  (privilege-aware: bold `sudo` + dim rest, else all-dim).

- **Pre-execution confirm.** Mutating verbs on a TTY emit `*_summary`
  then prompt `Proceed? [Y/n]` (or `[y/N]` for destroy: only destroy
  is N-default — muscle-memory ENTER must not delete). Skip
  conditions: dry-run (emits `(Real run would prompt: …)` preview),
  `--yes`, non-TTY stdin. On Abort: `Reporter::aborted()` + exit 0.
  Summary only emits when `cli.dry_run || stdin_is_tty`.

### Conventions

- **Acronym casing.** Rust convention treats acronyms as words: `Uid`
  not `UID`, `Macos` not `MacOS`. Method `lowest_free_uid`; struct
  `UidAllocator`. Identifiers (variables, fields, methods) keep the
  short Unix abbreviations `uid` / `gid` / `host` — they're domain
  vocabulary every operator carries from the shell.

- **Domain newtypes in `src/domain/ids.rs`.** `UserId(u32)` / `GroupId(u32)`
  wrap the POSIX numeric identifiers; `TenantUserName(String)` /
  `HostUserName(String)` wrap the macOS short usernames in their two
  distinct roles; `GroupName(String)` wraps the macOS short group
  name (today always `<tenant>-tenant-share`, built at the Tenants
  boundary by `tenants::tenant_share_group_name`). The `UserName`
  qualifier on the name pair is deliberate: bare `HostName` is a
  polyseme with the networking term (DNS hostname / `uname -n`); the
  qualifier disambiguates and the symmetric `TenantUserName` keeps
  the pair parallel. The bare nouns `host` and `tenant` persist in
  prose, in variable names, and in user-facing output strings.
  Validation for `TenantUserName` lives outside the constructor
  (`validate_name` at dispatch); the newtype is a tag, not a validity
  proof. Same for `GroupName` — `tenant_share_group_name` is the only
  producer today and appends the suffix to an already-validated tenant
  name.

- **Pure string formatters take `&str`, not the newtype.** `firewall::
  tenant_anchor_name(name: &str)`, `profile::display_path_for(name:
  &str)`, `doctor::pf_rule_presence_check(rules, tenant: &str)`,
  `doctor::has_group_acl_entry(listing, group: &str)`, etc., stay as
  `&str` parameters. Callers pass `name.as_str()` from a
  `&TenantUserName` (or `group.as_str()` from a `&GroupName`). The
  type-safety win is realized at the Tenants / HostUserDirectory / Reporter
  method boundaries and at ADT variants
  (`AccountOp::CreateTenantUser { name: TenantUserName, ... }`,
  `AccountOp::CreateShareGroup { group: GroupName, ... }`,
  `AclOp::Grant { group: GroupName, ... }`); pure helpers stay
  simple. Tests of pure helpers continue to use string literals
  directly.

- **Clap flag scoping.** `-v / --verbose`, `--dry-run`, `-y / --yes`
  are `global = true` on `Cli`. Per-subcommand flags (e.g.
  `--strict`, `--mode`) stay scoped to their verb.

- **Comment density is a symptom, not a goal.** Keep comments when
  WHY is non-obvious (hidden constraint, subtle invariant,
  bug-workaround, surprising behavior); drop when code/identifier
  says the same. Tracked source (`src/` + `tests/`) carries no cycle
  / Q-lock / SC references — a reader landing on the code in
  isolation should make sense of it. Tests follow the same rule, with
  one exception: sharpening / negative-pin comments survive (their
  WHY isn't carried by the test name).

## Test discipline

E2E-first. Bulk in `tests/cli_<verb>.rs` drives through `tenant::run`
with `StubUserDirectory` + `StubHostMachine`. `tests/cli.rs` holds parser
cross-cutting. Shared helpers in `tests/common/mod.rs`. Inline
`#[cfg(test)] mod tests` is out of style; standalone unit-test files
need explicit justification (per-substrate boundary pins for
`macos_host_machine.rs` / `macos_user_directory.rs`; combinatorial coverage on
pure functions for the parse/render/classify pin files).

`run_with(stub, args) -> (u8, String, String)` wires `NeverHostMachine`
(panics on any substrate call). `run_with_exec(stub, &StubHostMachine,
args)` lets the test own the host machine for real-mode assertions. Both
run in-process.

Behavioral assertions: op identity (`exec.account_ops()`,
`profile_ops()`, `firewall_ops()`, `logins()`, `exec_calls()`).
Display assertions: byte-exact. They pin the user-facing contract;
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

### Releases

- **Dev-suffix convention.** Main always carries `version = "X.Y.Z-dev"`
  in `Cargo.toml`. `tenant --version` from a main-branch build prints
  `tenant X.Y.Z-dev` so non-release binaries are instantly
  distinguishable from tagged releases. Release commits are the only
  commits where the version has no suffix.
- **Tag matches Cargo.toml by construction.** `just release-prepare
  X.Y.Z` is the only sanctioned way to tag. It strips `-dev`, refreshes
  `Cargo.lock`, commits, and tags `vX.Y.Z` in one recipe.
  `.github/workflows/release.yml` re-verifies in CI before building, as
  belt-and-suspenders against a manually-pushed tag.
- **Pre-1.0 bumps.** Minor (`0.1.0` → `0.2.0`) for user-visible
  behavior changes; patch (`0.1.0` → `0.1.1`) for bugfix-only.
- **Pre-release versions.** Use SemVer pre-release suffixes
  (`0.1.0-alpha.1`, `0.1.0-beta`, `0.1.0-rc.2`) to ship a tagged
  release that isn't yet stable. Pass the full version including
  suffix to `release-prepare`. The release workflow detects the `-`
  in the tag and passes `--prerelease` to `gh release create`, which
  marks the release with a "Pre-release" badge on GitHub and lets
  tooling filter it out from stable releases. After publishing a
  pre-release, `release-bump-dev` still takes the X.Y.Z target only
  (no suffix) — multiple pre-releases of the same X.Y.Z all bump back
  to the same `X.Y.Z-dev` dev state.
- **Release flow.** Edit `RELEASE_NOTES.md` with notes for the upcoming
  version → `just release-prepare X.Y.Z` → inspect (`git show vX.Y.Z`)
  → `just release-publish` (pushes commit + tag; Actions takes over
  from there) → wait for the GitHub Action to publish the release →
  `just release-bump-dev <NEXT>` to put main back into dev mode.
- **Operator install (pre-tap).** Until the Homebrew tap lands,
  operators install by downloading the release tarball from GitHub or
  `cargo install --git https://github.com/MuhammadFarag/tenant`.

Pre-commit hooks run `cargo fmt --check` and `cargo clippy
--all-targets -- -D warnings` on commits touching `.rs`. Local-only
(`language: system`). Run `pre-commit install` once after a fresh
clone.
