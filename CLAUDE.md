# tenant — Rust port of the macOS tenant-account CLI

A small CLI that provisions macOS user accounts, a primary share group
(`<name>-tenant-share`, UID/GID ≥600), a per-tenant TOML profile
(`~/.config/tenant/profiles/<name>.toml`), and a per-tenant PF anchor
(`/etc/pf.anchors/tenant-<name>`, referenced from `/etc/pf.conf`).

Verbs:
- `create <name>` — provision user + share group + cowork dir + login
  keychain + profile + PF anchor; enables pf.
- `destroy <name>` — convergent teardown (absent ⇒ noop; orphan-group ⇒
  converges); ends with `pfctl -a tenant-<name> -F all` to flush kernel
  rules. Leaves the cowork dir intact.
- `mode <name> install|runtime` — re-render anchor at the tier + reload
  pf (Light reapply).
- `inbound <name> restricted|permissive` — re-render anchor's inbound
  loopback section + reload pf; restricted gates on profile `[inbound]`
  ports (empty ⇒ locked), permissive opens all loopback TCP; egress renders
  at runtime steady-state (axes don't compose across commands).
- `shell <name> [--mode install|runtime] [--inbound restricted|permissive] [-- <cmd>]`
  — enter the tenant. Empty argv = interactive login; argv after `--` =
  single-command form. Light reapply (auto-narrow + host membership +
  tenant-side symlinks, no recursive ACL); install-mode widens for the call
  and narrows back. Command-form `--inbound permissive` widens inbound for
  the call then narrows back to restricted; interactive entry auto-narrows
  inbound to restricted. Child exit propagates; narrow-on-finally failure →
  `⚠` stderr warning that doesn't override the child's exit.
- `reload [<name>]` — canonical "apply everything": Full reapply (PF + host
  membership + symlinks + recursive `AclOp::Grant` per share +
  `EnsureCoworkDir`). Mode/shell skip the recursive passes; reload heals
  their drift. No-arg walks every tenant; exits 0 / 74.
- `doctor [<name>]` — read-only audit (paths, sudoers, pf, anchor, shares,
  group membership). `--strict` maps max severity to exit 1 / 2.
- `setup` — host-wide, opt-in host preparation (no tenant arg). A menu of
  opt-in items; today one: enable Touch ID for sudo (`PamOp`). Per-item
  prompt defaults to NO; non-TTY without `--yes` declines (auth-stack
  change must not auto-apply from a pipe); `--yes` accepts; `--dry-run`
  previews. No eligibility checks, no pre-exec doctor pass.

Follows Rust idioms: clap derive, composition-root DI, trait-object ports.

## Scope

Stable doctrine + a file map — facts about what the code currently does and
the non-obvious rules governing its shape. Per-cycle narrative lives in
`.features/roadmap-shipped.md`; chronology in `git log`. Don't grow this
file with shipped-feature recaps.

## File map

```
src/lib.rs        — `run` entry + module tree; re-exports Cli/Verb/ModeLevel/Terminal.
                    `run(Cli, &dyn HostUserDirectory, &dyn HostMachine, Terminal)` resolves
                    operator identity, swaps to DryRunHostMachine on --dry-run, hands to
                    commands::dispatch.
src/cli.rs        — clap surface: Cli/Verb/ModeLevel; global --verbose/--dry-run/--yes.
                    Argv parsed at the binary boundary.
src/terminal.rs   — Terminal { stdout, stderr, stdin, stdin_is_tty, colors }: operator-I/O
                    capability, built once at the boundary, threaded as one value to Reporter.
src/ansi.rs       — Colors per-stream gate; color wrappers; rule(title, width) divider.
src/domain/       — domain layer. host_user_directory.rs: HostUserDirectory trait (account-
                    inventory queries). host_machine.rs: HostMachine trait — the single host-
                    substrate port (describe_*/execute_* op pairs + non-unit carve-outs for
                    login/exec/reads/probes) + the WritableOp bridge. ops.rs: the Op ADT
                    (AccountOp/ProfileOp/FirewallOp/AclOp/KeychainOp/PamOp) + their WritableOp
                    impls. errors.rs:
                    per-domain error types. ids.rs: domain newtypes (UserId/GroupId/
                    TenantUserName/HostUserName/GroupName).
src/domain/tenants.rs / tenants/
                  — facade: Tenants + the generic run<O: WritableOp> narrate-execute-narrate
                    dispatcher + tenant_share_group_name + cowork_dir_path + guard_cowork_dir_kind.
                    Per-verb submodules own their full code (error type + impl Tenants block +
                    helpers): validation.rs, create.rs, destroy.rs, reapply.rs (mode/reload/
                    ReapplyScope/build_+execute_reapply_plan), shares.rs, shell.rs, doctor.rs,
                    setup.rs (host-wide opt-in host prep; SetupError).
src/domain/commands.rs
                  — verb dispatch (no I/O). Per-arm surface_*_error helpers route domain
                    errors to Reporter; builds ReapplyPlan upfront for prompt-bearing verbs so
                    profile-read failures surface pre-prompt.
src/domain/reporter.rs
                  — operator-facing output. Owns Terminal by value. section/ok/step/progress
                    vocab; per-verb _intent/_summary/_done triples; confirm/aborted/show_summary;
                    doctor_* audit surface.
src/adapters/     — driven adapters. macos/user_directory.rs (MacosUserDirectory — ZST, per-call
                    dscl, eDSRecordNotFound absence). macos/host_machine.rs (MacosHostMachine —
                    production substrate; owns all argv + privileged writes). dry_run_host_machine.rs
                    (DryRunHostMachine — no-op execute; describe delegates; reads return placeholders).
src/allocation.rs — UidAllocator + GidAllocator, independent, both from TENANT_UID_FLOOR = 600.
src/profile.rs    — TOML serde + parse (schema-version + $HOME prefix-only); expand_tenant_path;
                    default_profile_toml.
src/firewall.rs   — pure: render_anchor, anchor-ref helpers, tenant_anchor_name/_path.
src/doctor.rs     — pure grep-and-classify: Finding/Severity/Category/SymlinkActual + parse/classify
                    fns. All I/O lives in Tenants::doctor_*.
src/main.rs       — composition root: prod impls + tenant::run; reads $USER, probes TTY + colors.

tests/cli_*.rs            — E2E, one binary per verb + cli.rs for parser cross-cutting. Each
                            declares `mod adapters; mod common;`.
tests/common/mod.rs       — output/plan builders, runners (run_with, run_with_exec,
                            run_with_stdin), stub-factory helpers. TEST_HOST.
tests/adapters/           — test-only impls: StubHostMachine (records every op + failure injection
                            + builder preload), StubUserDirectory (HashMap inventory + per-method
                            failure queues), NeverHostMachine (panics; default for run_with).
tests/macos_host_machine.rs — per-variant pins of describe_* argv contracts.
tests/intent_labels.rs    — per-variant Op::intent_label() pins.
tests/macos_user_directory.rs — dscl smoke + eDSRecordNotFound pin (cfg target_os = "macos").
tests/doctor.rs           — combinatorial classify matrix, Finding display/guidance, severity order.
tests/{env_policy,pf_rule,pam,host_acl,profile,firewall_render,firewall_conf}_parse.rs
                          — combinatorial on the pure fns in doctor.rs / firewall.rs.
```

## Project doctrine

Rules a cold code-reader could plausibly violate — each encodes a decision
already made.

### ADT + trait shape

- **Intent / mechanism split.** Domain ops (`AccountOp`/`ProfileOp`/
  `FirewallOp`/`AclOp`/`KeychainOp`/`PamOp`) express *what*;
  `MacosHostMachine` owns argv — Tenants never builds argv. Tests assert op
  identity; literal shell shape is pinned in `tests/macos_host_machine.rs`,
  one test per variant.
- **`PamOp` is the host-config sub-domain for `tenant setup`** — named by
  substrate (`/etc/pam.d`), sibling-by-shape to the parked `SudoersOp`
  brief, not by the verb. One variant today (`EnableTouchIdForSudo`),
  reusing `HostFileError`. A planned mutation that fits `Result<(), E>` ⇒
  ADT variant (not a carve-out). `execute_pam` is self-idempotent: it
  no-ops when `pam_tid` is already present in EITHER `/etc/pam.d/sudo` or
  `/etc/pam.d/sudo_local`, so the verb can offer unconditionally (no
  pre-probe) without ever appending a duplicate directive.
- **One `HostMachine` trait; sub-domains as method-pairs.** A new sub-domain
  extends `HostMachine` with a `describe_*`/`execute_*` pair + a leaf
  `Op<'_>` variant — no new trait. The single `HostMachine` is the one test
  seam at the host boundary.
- **Carve-out methods for non-unit returns.** Methods that don't fit
  `Result<(), E>` are called directly by Tenants: `login`/`exec_as_tenant`
  (stdio inherit, i32 exit), content reads (`String`), probe verdicts
  (enum/bool). `AccountOp::LoginAsUser`/`ExecAsUser` exist only for plan/echo
  render (`execute_account` panics on them). New method: fits
  `Result<(), E>` → ADT variant; else → carve-out.
- **Probe via HostMachine, not HostUserDirectory re-read.** Mid-execution OS
  re-checks (destroy's residue probe) are regular substrate calls whose
  `Ok`/`Err` drives a branch. HostUserDirectory is for up-front inventory
  queries; per-mutation follow-up probes live on HostMachine.
- **Host-side vs tenant-side path probes.** `tenant_path_kind` probes via
  `sudo -n -u <tenant>` (paths whose accessibility is the tenant's
  perspective — share `tenant_path`s); `host_path_kind` probes the host fs
  directly, no sudo (host-owned paths — cowork dirs). Pick by ownership: the
  tenant-side probe breaks when the tenant user is absent (orphan-group
  destroy, post-delete tail), so host-owned checks must use `host_path_kind`.
- **Doctor probes are carve-out methods, not `Op<'a>` variants.** Probes are
  how doctor LEARNS, not what the verb DOES — no `Op::Doctor`.
- **`HostFileError` covers multiple host-config substrates** (sudoers +
  drop-ins, pam.d/sudo, on-disk anchor). Reuse, don't make per-substrate
  types; the error's Display names the path.
- **`LoginAsUser`/`ExecAsUser`/`EnsureDirAsUser`/`EnsureSymlinkAsUser` group
  under `AccountOp`** by their shared `sudo -[in] -u <tenant>` mechanism.
  The first two carve out to `login`/`exec_as_tenant`; the other two flow
  through `execute_account`.

### Layering + DI

- **No I/O in command logic.** `commands::dispatch` and `Tenants` call
  Reporter's verb-named methods; neither touches raw writers nor checks
  `cli.verbose`/`cli.dry_run`. Mode/verbosity branching lives in Reporter.
- **Composition-root DI.** `tenant::run` takes `Cli` + `&dyn
  HostUserDirectory` + `&dyn HostMachine` + `Terminal`. Argv parsing at the
  binary boundary (`main.rs` `Cli::parse()`; tests `try_parse_from`). Prod
  impls in `main.rs`; tests build stubs. Tenants + Reporter built inside
  `run`; both swap to `DryRunHostMachine` on `--dry-run`. Test seam stays at
  the HostMachine boundary.
- **Adapters live under `.../adapters/`** — production-reachable in
  `src/adapters/`, test-only (`StubHostMachine`/`StubUserDirectory`/
  `NeverHostMachine`) in `tests/adapters/`. Keeps the library surface free of
  test scaffolding.
- **Terminal is the capability, not a bundle.** All operator I/O is carried
  by `Terminal`, threaded as one value; Reporter owns it by value. Any
  function needing operator I/O takes `Terminal` whole, even to write one
  field — don't carve out `fn h(stderr: &mut dyn Write)` shapes.
- **Per-call dscl on `HostUserDirectory`.** ZST; each method spawns dscl per
  call, no cache. Absence is the `eDSRecordNotFound` stderr signal, not
  any-nonzero (preserves frame contracts when dscl itself breaks). Latency is
  invisible on a solo-Mac CLI.

### Verb semantics

- **Lexical → state check order.** `validate_name` (charset) before
  `check_conflict`/`destroy_eligibility` (OS state). Cheaper failure first.
- **Convergent teardown.** `destroy` against an absent tenant is a successful
  noop; absent user + leftover group routes to `destroy_orphan_group` (full
  idempotent PF teardown, so partial-create state also converges).
- **Centralized name builders.** `tenant_share_group_name(name)`,
  `firewall::tenant_anchor_name`/`_path`. Don't inline `format!`.
- **Decoupled UID/GID allocation.** `UidAllocator` reads `used_uids`,
  `GidAllocator` reads `used_gids` — disjoint, may diverge (UID 613, GID 600).
  Don't fuse.
- **Tenant-floor guard on destroy.** `destroy_eligibility` refuses
  (`EX_USAGE 64`) when the account's UID is below `TENANT_UID_FLOOR`
  (`NotATenant`) or non-positive (`SystemAccount`). Charset rail upstream,
  floor downstream.
- **Exit codes.** `0` success (incl. destroy noop, orphan convergence,
  doctor's default informational). `64` (`EX_USAGE`) user-input failure
  (validation/conflict/refusal). `74` (`EX_IOERR`) substrate failure on every
  verb except shell. Shell propagates the child's exit (clamped 0..=255);
  command-form narrow-on-finally failure doesn't override it. `1` is clap's
  parse-error / `ModeLevel`-rejection default. Doctor `--strict`: `1`
  warning, `2` critical; without it, `0`.

### Create + teardown

- **Create partial-failure recovery.** `CreateError::UserWithRollback` emits
  original + rollback-failed hint. Profile/Firewall/CoworkDir/Keychain
  failures leave state on host; recovery is `tenant destroy <name>`
  (idempotent on PF). On PF Reload failure, Tenants runs a 4-step
  auto-recovery (RestoreConfigFromBackup → RemoveAnchor → Reload →
  FlushAnchor) before surfacing; recovery-of-recovery →
  `FirewallError::RestoreFailed` with a manual hint. `PostProvision(ModeError)`
  recovers via `tenant reload` (not create — would name-conflict).
- **`KeychainOp::CreateLoginKeychain` is idempotent against a duplicate
  keychain.** The adapter swallows the `create-keychain` "already exists"
  stderr (case-insensitive substring, not exit code — macOS shifts it) as
  `Ok` and re-applies the other 3 natively-idempotent `security` calls. Same
  posture as `pfctl -e "already enabled"` / `chmod +a`. The other 3 aren't
  pre-guarded; partial state is cleaned by destroy moving the home to
  `/Users/Deleted Users/`.
- **`tenant shell` unlocks the tenant's login keychain before exec.** Shared
  pre-spawn step on both shell paths (after `execute_reapply_plan`, before
  login/exec): `find_stashed_password` (`security find-generic-password …`)
  then `unlock_tenant_keychain` (`sudo -iu <name> security unlock-keychain …`).
  Both HostMachine carve-outs (no `KeychainOp` — mechanism, not a planned op).
  `KeychainError::NotFound` → `ShellError::StashAbsent` → `EX_USAGE` with a
  refusal naming `tenant destroy <name> && tenant create <name>` (legacy
  migration); other errors → `UnlockFailed` → `EX_IOERR`. Already-unlocked is
  a substrate no-op. No `Finding::TenantKeychainLocked` probe —
  `security show-keychain-info` via `sudo -iu` triggers SecurityAgent on
  Darwin 25.x.
- **PF anchor flush is load-bearing on destroy.** `pfctl -f` does NOT GC
  anchors whose `load anchor` directive was removed — without
  `pfctl -a tenant-<name> -F all` the old rules persist in kernel memory and
  the next tenant reusing the UID inherits them. `FirewallOp::FlushAnchor` is
  the final step on both destroy paths + create-side reload-failure recovery.
  Negative pin: create's success path and the reapply paths do NOT flush
  (they leave `load anchor` in place for `pfctl -f` to re-read).

### Reapply (mode / shell / reload)

- **Two anchor axes; every reapply renders both, the uncontrolled one to
  steady state.** Egress (hosts, `hosts_for_level`) and inbound loopback
  (`InboundRules`, `inbound_rules_for_level`/`steady_inbound_rules`) resolve
  independently in `reapply.rs` before `render_anchor`. A verb controls one
  axis and pins the other to steady: `tenant inbound` → egress at runtime
  tier; `tenant mode` → inbound at restricted(profile ports);
  `reload`/`create`/shell-interactive → both steady. The two widenings do NOT
  compose across separate commands (no state file — implicit-current-mode
  doctrine); `restricted` is surface-reduction, not host-vs-peer isolation (a
  declared port is reachable by host AND peer tenants; a tenant can't reach its
  own undeclared port; UDP is unfiltered — TCP only). lo0 empirical record
  (`.features/loopback-cross-tenant-isolation.md`): pf tags do NOT survive the
  lo0 out→in hop and host-egress state does NOT bridge it, so initiator
  identity is unrecoverable — only permissive (all-ports stateless) and
  restricted-by-port (`pass in port … no state` + `block drop in flags S/SA`)
  are physically realizable.
- **`ReapplyScope::{Light, Full}` splits reapply by cost.** Light (mode +
  shell) omits the recursive ACL passes (`AclOp::Grant` per share +
  `EnsureCoworkDir`); PF anchor + Reload + `AddHostToShareGroup` + per-share
  `EnsureDirAsUser`/`EnsureSymlinkAsUser` still fire. Inheritable ACE bits
  (`file_inherit,directory_inherit`) propagate the grant to tenant-created
  children, so the recursive walk is redundant in steady state. Full (reload +
  create-post-provision) runs both recursive passes. Light-skipped drift
  surfaces via doctor; remediation is `tenant reload`.
- **Mode/shell/reload share `build_reapply_plan` + `execute_reapply_plan`,
  parameterized by scope.** Build is separate from execute so dispatch can
  render the upfront plan + surface profile-read failures pre-prompt. The
  share pass runs AFTER PF reapply lands (a Reload failure aborts before any
  ACL/symlink mutation). `execute_share_ops` is shared with
  `reapply_shares_post_provision` (create's post-Enable pass; skips PF;
  hardcoded Full so the first apply's recursive grant reaches pre-existing
  files).
- **`tenant shell` collapses interactive + command forms** on argv presence
  (prior art: kubectl/docker/ssh/sudo). Clap `last = true` on `argv` requires
  `--`; `requires = "argv"` on `--mode` rejects bare
  `tenant shell <name> --mode install` at parse. No confirm on either form.
- **Command-form narrow-on-finally is gated on `mode == Install`.** Runtime
  entry IS the runtime posture (a second reapply = zero delta, skip). Install
  entry widens; the post-child runtime reapply is mandatory regardless of
  child outcome. Widen-build failure skips the narrow; widen-execute failure
  runs a best-effort inline narrow. Child exit propagates; narrow failure →
  `⚠` warning that doesn't override it. `ShellError::NarrowFailed
  { child_exit, narrow_err }` carries both.
- **Auto-narrow protects only the `tenant shell` entry path.** `sudo -iu
  tenant` bypasses the binary and inherits the current posture;
  `tenant shell` is the canonical entry.

### Shares

- **Per-tenant `[[shares]]` are profile-driven.** Each entry is `(host_path,
  mode {ro|rw}, tenant_path)`. `host_path` literal absolute; `tenant_path` a
  template with `$HOME` prefix-only resolution (position 0; mid-string refuses
  at parse). Mode `ro`/`rw` only (POSIX bit-strings rejected — file-vs-dir
  semantics diverge). Pre-flights before any substrate: `host_path.exists()` +
  `tenant_path_kind` reject `HostPathMissing`/`TenantPathOccupied`. Removed
  entries aren't auto-revoked; doctor surfaces orphans.
- **`AclOp::Grant`/`Revoke` are chmod-+a-natively-idempotent.** Grant =
  `sudo chmod -R +a "group:<g> allow <bits>" <path>`; Revoke =
  `chmod -a … <path>` (no sudo, no `-R`). Bits: ro =
  `read,execute,file_inherit,directory_inherit`; rw adds
  `write,delete,append`. No substring pre-check (macOS canonicalizes bit
  names, defeating exact-match). Grant fires only under Full (reload +
  create-post-provision); it recurses so shares on already-populated dirs
  reach existing children, and the inheritable bits cover children created
  later. Grant runs under `sudo` because tenant-written files in a rw share
  are tenant-owned and POSIX requires owner-or-root to modify an ACL
  (share-group rw lacks `writesecurity`) — without sudo the second reapply
  EPERMs on every tenant-owned descendant. Revoke stays single-pass +
  top-level: `chmod -R -a` fails on any node missing the ACE, and inherited
  child ACEs go orphan-inert once the share group is removed in destroy.
  Pre-existing-file drift → doctor `AclDrift`, remediated by `tenant reload`.
- **`chmod -R +a` adds a direct ACE on every node even when an inherited copy
  exists** (macOS doesn't dedupe across the direct/inherited boundary). Files
  present at apply time end up with two `ls -le` entries (one direct, one
  inherited); +a stays idempotent against the direct duplicate so it doesn't
  accumulate further — a bounded, inert one-time +1. Not worth a
  strip-and-regrant (same `chmod -R -a` asymmetry that keeps Revoke
  single-pass).
- **`tenant_path_kind` returns `PathKind { Absent, Symlink(target), Dir,
  Other }`.** `Dir` vs `Other` lets the cowork pre-flight accept an existing
  dir (mkdir-p no-ops) while refusing `Other`. Shares' `build_share_ops`
  refuses both `Dir` and `Other` as `TenantPathOccupied`. `Symlink` is the
  idempotent re-link; target stored verbatim from readlink so `SymlinkDrift`
  compares against `host_path` in one trip.
- **Host operator is a secondary member of every tenant's share group.**
  Added at create (`AddHostToShareGroup`, between `CreateShareGroup` and
  `CreateTenantUser`); removed at destroy (`RemoveHostFromShareGroup`, which
  checkmembers first). `execute_reapply_plan` re-adds on every reapply as
  catch-up. *Limitation:* macOS snapshots a process's supplementary groups at
  creation, so the operator's current shell won't see new membership until a
  new Terminal opens.

#### Co-working dirs

- **Per-tenant cowork dir at `/Users/Shared/tenants/<name>`.** Owner = host
  operator, group = `<name>-tenant-share`, mode `2770` (setgid + group-rwx +
  zero-other), with an inheritable rw ACL matching a rw share's bits. Setgid
  propagates the group to children; the inheritable ACL propagates the rw bits
  — together making tenant-created files collaboratively reachable without a
  tenant umask change.
- **Cowork dirs are CREATED by tenant, not granted on pre-existing content**
  (inverse of `[[shares]]`). Mode + ACL are tenant-managed end-to-end: the
  substrate `mkdir`s, `chown`s, `chmod`s, and grants the inheritable ACL.
- **`AccountOp::EnsureCoworkDir` is one variant, four substrate calls:**
  `mkdir -p` → `chown <host>:<group>` → `chmod 2770` → `chmod -R +a` rw bits.
  Each natively idempotent. `describe_account` returns a `\n`-separated
  multi-line string; Reporter emits one privilege-aware line per call.
- **`EnsureCoworkDir` fires at create AND under Full reapply (reload only).**
  Create inserts it between `CreateTenantUser` and the keychain bootstrap;
  `build_reapply_plan` adds it under Full only. Light (mode + shell) OMITS it
  (4th call is recursive). Inheritable bits make skipping the recursive walk
  sound in steady state. Drift → doctor `CoworkDirAbsent`/`CoworkAclDrift`,
  remediated by reload. Create failure → `CreateError::CoworkDir` at
  `EX_IOERR`; recovery is `tenant destroy`.
- **Path builder at the Tenants boundary.** `cowork_dir_path(name: &str) ->
  PathBuf` (`/Users/Shared/tenants/<name>`); `COWORK_DIR_PARENT` carries the
  prefix as one source. Takes `&str` (the newtype lifts at the ADT variant,
  not the builder).
- **Cowork-path kind-check fires under Full scope only.** `mkdir -p` errors on
  a regular file and silently follows a symlink (then chown/chmod mutate the
  link target). Create + Full `build_reapply_plan` probe first via
  `guard_cowork_dir_kind`: `Absent`/`Dir` continue, `Symlink`/`Other` refuse
  with `AccountError::CoworkDirOccupied` (→ `CreateError::CoworkDir` /
  `ModeError::Account`). Light skips both op and guard. Prevents the substrate
  following a symlink — state-machine concern, not a race.
- **`tenant destroy` does NOT remove the cowork dir** (it holds operator
  work). Both destroy paths emit a one-line stdout notice before the
  `─── Done ───` divider naming the intact path, probed via `host_path_kind`
  (host-side, no sudo — works even when the tenant user is gone). Convergent:
  `Absent` → no notice; otherwise notice; probe error → `⚠` stderr warning and
  destroy continues.

### Host setup (`tenant setup`)

- **`setup` is host-wide, not per-tenant.** No name argument, no
  eligibility/name checks, no pre-exec doctor pass. It prepares the HOST to
  run tenants — a menu of opt-in items (today one: Touch ID for sudo). Lives
  in `tenants/setup.rs` (`SetupError` + `Tenants::setup`); dispatch routes
  the outcome with no plan-build or confirm orchestration.
- **Touch ID is an OFFER, not a fix.** It has no ground truth in any
  profile — it's an optional host capability (`Finding::TouchIdMissing` is
  Info, never trips `--strict`). So `doctor` does NOT carry a `--fix`; it
  points at `setup`, which *offers* and lets the operator decline. Declining
  is first-class and stateless — no suppression file (implicit-current-mode
  doctrine); a declined item just keeps surfacing the dim Info line.
- **Per-item confirm diverges from `confirm`.** `setup`'s offer defaults to
  NO (`[y/N]`) and a non-TTY without `--yes` DECLINES — the opposite of
  create/destroy (which proceed on non-TTY). An auth-stack change must never
  auto-apply from a pipe. `--yes` accepts; `--dry-run` previews (the offer
  returns Proceed with a `(Real run would prompt: …)` line). Logic lives in
  `Reporter::setup_offer`, not in `Tenants` (no `cli.dry_run` in command
  logic).
- **No pre-probe for "already enabled".** The item is always offered;
  `execute_pam` is self-idempotent (no-ops if `pam_tid` is in either pam
  file). This keeps `--dry-run` honest — the preview never depends on
  probing placeholder host state — and mirrors every other verb's
  static-plan + idempotent-execute shape. Re-running `setup` re-offers; a
  yes on an already-configured host is a substrate no-op.
- **Touch ID targets `/etc/pam.d/sudo_local`, not `/etc/pam.d/sudo`.** The
  sudo file is clobbered by macOS updates and `include`s `sudo_local` as its
  first auth directive, so the append survives updates and lands first in the
  stack. `execute_pam` backs up `sudo_local` (`.tenant-backup`) before an
  append-only stdin-fed `sudo tee -a` (no shell pipe).

### Doctor

- **Touch-ID detection reads BOTH pam files.** `check_touch_id_for_sudo`
  short-circuits: a `pam_tid` directive in `/etc/pam.d/sudo` returns clean
  without touching `sudo_local`, else `read_pam_sudo_local` (ENOENT ⇒
  `Ok("")`, the common case) is consulted. Reading only `/etc/pam.d/sudo`
  false-positived `TouchIdMissing` on a host set up the sanctioned way. The
  finding's copy is an offer pointing at `tenant setup`, not a `sed` command.
- **Probe-as-tenant subsumes ACL semantics at the kernel level.**
  Filesystem-exposure detection runs `sudo -n -u <tenant> /bin/test -<r|x>
  <path>` and treats the exit code as ground truth (0 Allowed / 1 Denied /
  else Unknown) — the kernel composes POSIX + ACL + sandbox + TCC, so no
  effective-access model. Per-utility absolute paths are load-bearing on
  Darwin 25.x: `/bin/test`, `/bin/ln`, `/bin/mkdir`, `/usr/bin/readlink`
  (`/usr/bin/test`, `/bin/readlink` absent). `Denied` doesn't say WHY — that's
  the remediation surface's job.
- **`DoctorScope::Shell` covers both shell forms** (no `Exec` variant):
  `PfDisabled` + `EnvLeak` host-wide + all per-tenant drift.
- **`DoctorScope::Mode` shares the per-tenant drift set with `Shell`/`Reload`**
  (Light reapply no longer auto-heals share/cowork, so the audit surfaces it).
  `EnvLeak` stays Shell-only (only shell's exec inherits `SSH_AUTH_SOCK`).
- **Only unqualified `Defaults env_delete` counts as protection.**
  `has_env_delete_for` accepts only the unqualified form (not
  `Defaults:user`/`>runas`/`@host`/`!cmd`); a qualified directive
  false-positives, recovered by adding the unqualified one.
- **PF rule presence is structural, not exact-match.** `pf_rule_presence_check`
  wants at least one `pass ` and one `block ` line (whitespace stripped,
  comments skipped) — pfctl's format isn't a stable contract, so structural
  presence catches "anchor empty/wrong" without cosmetic false-positives.
- **Anchor-body drift is file-side, byte-exact, runtime-tier-only.**
  `anchor_body_matches` is byte-exact vs `render_anchor(name, runtime_hosts)`
  (deterministic renderer ⇒ any diff is real). Runtime tier only — install-tier
  widening outside a shell session IS drift. Profile read/parse failure skips
  silently.
- **Inbound-exposure finding composes intent + observed posture.**
  `check_inbound_exposure` reads the profile's declared `[inbound]` ports
  (intent) and the on-disk anchor's permissive flag (`anchor_is_permissive`,
  the current posture — there's no state file), then
  `classify_inbound_exposure` resolves: permissive (the widen left behind)
  wins → `InboundPermissive` (Warning); else non-empty ports →
  `InboundExposure` (Info, names the ports); else locked → quiet. Honest scope
  baked into the text: restricted is surface-reduction, NOT host-vs-peer
  isolation — a declared port is reachable by the host AND peer tenants (pf
  can't see the initiator on shared 127.0.0.1); a tenant can't reach its own
  undeclared port; UDP loopback is unfiltered (TCP only). The shell-entry
  posture line (`doctor_inbound_posture`) is CALIBRATED and distinct from the
  `⚠ Doctor: N warning(s)` aggregate: locked = quiet, restricted-with-ports =
  a dim `inbound: restricted — :N open …` line, permissive = a loud
  `⚠ inbound: PERMISSIVE …` warning. Emitted directly (not via the pre-exec
  `record` closure) so Info exposure never inflates the warning count.
- **Findings carry a 4-section guidance block (Why / Fix / Side-effects /
  Alternative).** Sentence-case headers, imperative fix, literal tenant name
  in per-tenant variants; variants without a distinct command omit
  Alternative; `FilesystemExposure` returns none. New `Finding` variants
  author `guidance()` + a byte-form pin in `tests/doctor.rs`.
- **Pre-exec doctor summary on mutating verbs.** Each runs a verb-relevant
  subset between `*_summary` and confirm. Criticals emit inline; Warning+Info
  aggregate into one `⚠ Doctor: N warning(s) …` line. Healthy host: nothing.
  Substrate-machinery failures → `doctor_*_failed` stderr frame and the verb
  proceeds — the audit is a courtesy, never an abort gate.
- **Point-of-use sudo; precise pre-pass gate.** Doctor's host-config reads
  (`read_pf_status`, `read_kernel_pf_rules`, `read_env_policy`) use bare `sudo`
  (no `-n`), so the first privileged probe prompts-and-caches and later
  `sudo -n -u` probes ride the timestamp. The cache *check*
  `sudo_session_cached` (`sudo -n -v`) keeps `-n` (fail-closed on spawn error).
  `pre_exec_doctor_summary` reads it once and gates ONLY the genuine sudo
  probes (incl. the `tenant_path_kind` SymlinkDrift half of share drift) —
  uncached ⇒ they skip silently, no prompt, no spam. Auth-free drift
  (anchor-body, cowork, host-in-group, the `read_host_acl` AclDrift half) runs
  regardless. The split is a caller-side decision (`collect_share_drift` takes
  `sudo_cached: bool`); no interactivity flag leaks into a probe signature.
  Non-TTY doctor still fails rather than prompts (out of scope).

### Operator UX + plan rendering

- **Plan rendering pre-confirm, verbose-gated.** Prompt-having verbs
  (`create`/`destroy`/`mode`/single-tenant `reload`) render the `Plan
  (commands to execute):` section inside `*_summary`, verbose only; non-prompt
  verbs (`shell`, no-arg `reload`) keep plan in the verb. Layout: `  •
  <intent>[  # <annotation>]` + indented privilege-aware shell line (bold
  `sudo` + dim rest, else all-dim).
- **Pre-execution confirm.** Mutating verbs on a TTY emit `*_summary` then
  `Proceed? [Y/n]` (`[y/N]` for destroy — only destroy is N-default so
  muscle-memory ENTER doesn't delete). Skip on dry-run (emits `(Real run would
  prompt: …)`), `--yes`, non-TTY stdin. Abort → `aborted()` + exit 0. Summary
  emits only when `dry_run || stdin_is_tty`.

### Conventions

- **Acronym casing.** Acronyms are words: `Uid` not `UID`, `Macos` not `MacOS`
  (`UidAllocator`, `lowest_free_uid`). Identifiers keep the short Unix
  abbreviations `uid`/`gid`/`host`.
- **Domain newtypes in `src/domain/ids.rs`.** `UserId`/`GroupId` wrap POSIX
  numbers; `TenantUserName`/`HostUserName` wrap the two username roles;
  `GroupName` wraps the share-group name. The `UserName` qualifier
  disambiguates `HostName` from the networking term and keeps the pair
  parallel. Bare `host`/`tenant` persist in prose, variables, and output.
  Newtypes are tags, not validity proofs — `TenantUserName` validation lives
  at dispatch (`validate_name`); `GroupName` is built only by
  `tenant_share_group_name`.
- **Pure string formatters take `&str`, not the newtype** (`tenant_anchor_name`,
  `display_path_for`, `pf_rule_presence_check`, …); callers pass
  `name.as_str()`. The type-safety win is at the Tenants/HostUserDirectory/
  Reporter boundaries and ADT variants; pure helpers stay simple.
- **Clap flag scoping.** `-v/--verbose`, `--dry-run`, `-y/--yes` are `global`;
  per-verb flags (`--strict`, `--mode`) stay scoped.
- **Comment density is a symptom, not a goal.** Keep comments where WHY is
  non-obvious; drop when the code says it. Tracked source carries no
  internal planning-process references. Tests follow suit, except sharpening/negative-pin
  comments survive.

## Test discipline

E2E-first. Bulk in `tests/cli_<verb>.rs` through `tenant::run` with
`StubUserDirectory` + `StubHostMachine`; `cli.rs` holds parser cross-cutting;
shared helpers in `tests/common/mod.rs`. Inline `#[cfg(test)] mod tests` is out
of style; standalone unit files need justification (substrate-boundary pins;
combinatorial pure-fn coverage). `run_with` wires `NeverHostMachine` (panics on
any substrate call); `run_with_exec` lets the test own the host machine.
Behavioral assertions = op identity; display assertions = byte-exact (cosmetic
message tweaks need test edits).

## Local dev

```
just check   # fmt + clippy -D warnings + test (pre-merge gate)
just fmt     # in-place format
just test    # cargo test
just run create somename --dry-run -v   # invoke the binary; args after `run` forward
just build   # release binary at target/release/tenant
just install # cargo install --path . (puts `tenant` on PATH via ~/.cargo/bin)
```

Pre-commit hooks run `cargo fmt --check` + `cargo clippy --all-targets -- -D
warnings` on `.rs` commits (local-only; `pre-commit install` once after clone).

### Releases

- **Dev-suffix convention.** Main always carries `version = "X.Y.Z-dev"`;
  release commits are the only suffix-free ones, so `tenant --version` flags
  non-release builds.
- **Tag matches Cargo.toml by construction.** `just release-prepare X.Y.Z` is
  the only sanctioned tag path (strips `-dev`, refreshes `Cargo.lock`, commits,
  tags `vX.Y.Z`); CI re-verifies.
- **Pre-1.0 bumps.** Minor for user-visible behavior, patch for bugfix-only.
  Pre-release suffixes (`0.1.0-alpha.1`, `-rc.2`) ship tagged-but-unstable; the
  `-` in the tag drives `--prerelease`. `release-bump-dev` takes the X.Y.Z
  target only (no suffix).
- **Release flow.** Edit `RELEASE_NOTES.md` → `just release-prepare X.Y.Z` →
  inspect (`git show vX.Y.Z`) → `just release-publish` (pushes commit + tag;
  Actions builds) → wait for the Action → `just release-bump-dev <NEXT>`.
- **Operator install (pre-tap).** Download the release tarball, or `cargo
  install --git https://github.com/MuhammadFarag/tenant`.
