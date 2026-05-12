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
anchor's in-kernel rules.

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
src/lib.rs        — public API: pub fn run; declares modules; Cli + Verb + parse;
                    composition-root mode swap (DryRunExecutor when cli.dry_run);
                    constructs Reporter with the active Executor reference so
                    plan + echo lines render lazily via Op::describe_via.
src/commands.rs   — dispatch (the match on Verb) — no I/O, no cli.dry_run check.
                    Calls Reporter's verb-named methods directly: refuse_*
                    methods for validation / conflict / eligibility refusals;
                    create_group_failed / create_failed / create_rollback_failed
                    / create_profile_failed / create_firewall_failed for
                    create's five error variants; destroy_failed /
                    destroy_profile_failed / destroy_firewall_failed via
                    `surface_destroy_error` for both destroy arms;
                    shell_failed for shell spawn failures; destroy_absent for
                    the convergent noop. Create-side matches
                    CreateError::{Group, User, UserWithRollback, Profile,
                    Firewall}; destroy-side matches the 5-variant Eligibility
                    and surfaces DestroyError::{Account, Profile, Firewall}.
                    Shell-side reuses the same Eligibility classifier but
                    collapses NotPresent + OrphanGroup into a single
                    `refuse_shell_absent` refusal (the operator wants a
                    shell; the lingering group alone can't host one) and
                    clamps the child shell's i32 exit code into u8 for
                    propagation.
src/accounts.rs   — Reader trait + StubReader / MacosReader (dscl);
                    Writer struct (composes AccountOp / ProfileOp / FirewallOp
                    values into verb-level flows, hands them to the Executor
                    via the generic `run<O: WritableOp>` helper);
                    validate_name, check_conflict, destroy_eligibility.
                    `tenant_share_group_name(name)` is the single source of
                    truth for the `<name>-tenant-share` suffix. `create_tenant`
                    builds CreateShareGroup → CreateTenantUser ops (with a
                    DeleteShareGroup rollback annotated `# on rollback`) →
                    ProfileOp::Create → (read_profile + parse + read_pf_conf
                    + render_anchor + ensure_anchor_ref to compose the
                    firewall payloads) → BackupConfig → InstallAnchor →
                    UpdateConfig → Reload (with restore→remove-anchor→reload→
                    flush-anchor recovery annotated `# on reload failure`) →
                    Enable; returns `CreateError`. `destroy_tenant` builds
                    DeleteTenantUser → LookupUserRecord (probe; success
                    gates the conditional DeleteUserRecord cleanup) →
                    DeleteShareGroup → ProfileOp::Delete → BackupConfig →
                    RemoveAnchor → UpdateConfig → Reload → FlushAnchor;
                    returns `DestroyError`. `destroy_orphan_group` is the
                    7-op convergence path (DeleteShareGroup +
                    ProfileOp::Delete + the same 5-step PF teardown).
                    `shell_into_tenant` builds a LoginAsUser op solely for
                    plan rendering and dispatches through `Executor::login`,
                    returning the child shell's i32 exit code. The private
                    `run<O: WritableOp>` helper couples per-step `$` echo +
                    execute into one call. `parse_id_line` is the shared
                    parser for both UID and GID dscl listings (negative-ID
                    filter + lowest-wins fold).
src/allocation.rs — UidAllocator + GidAllocator (both iterate from
                    TENANT_UID_FLOOR = 600; consult disjoint Reader maps,
                    independent values)
src/executor.rs   — Per-domain Op enums + unified Executor substrate + the
                    `Op` ADT root + `WritableOp` trait bridge.
                    `AccountOp` variants: CreateShareGroup, DeleteShareGroup,
                    CreateTenantUser, DeleteTenantUser, LookupUserRecord (the
                    dscl-read probe; success means record present),
                    DeleteUserRecord (the dscl-delete cleanup), LoginAsUser
                    (used only for `describe_account`; execution goes through
                    `login`). `ProfileOp` variants: Create, Delete.
                    `FirewallOp` variants: InstallAnchor { name, body },
                    RemoveAnchor { name }, BackupConfig,
                    RestoreConfigFromBackup, UpdateConfig { content }, Reload,
                    FlushAnchor { name }, Enable. `Anchor` stays in the
                    variant names (the project's vocabulary for "named
                    per-tenant firewall ruleset"); `Pf` prefixes drop because
                    the tool name lives in `MacosExecutor`. `Executor` trait
                    methods: per-domain `describe_*` (operator-facing display
                    lines, used by both the upfront plan block and the `$`
                    echo lines) + `execute_*` (perform the side effect)
                    pairs for account / profile / firewall; plus the three
                    carve-out methods whose return types don't fit
                    `execute_*`'s unit shape — `login(name) -> Result<i32,
                    AccountError>` (interactive path with inherited stdio
                    and child exit code), `read_profile(name) ->
                    Result<String, ProfileError>` (returns the on-disk
                    profile content), and `read_pf_conf() -> Result<String,
                    FirewallError>` (returns the on-disk pf.conf content).
                    `Op<'a>` is the top-level ADT wrapper for "any op,
                    regardless of domain" — variants are Account(&AccountOp),
                    Profile(&ProfileOp), Firewall(&FirewallOp).
                    `Op::describe_via(executor)` is the one place that matches
                    on domain for display purposes, dispatching to
                    `executor.describe_{account,profile,firewall}`. The
                    Reporter uses Op for both upfront plan rendering and
                    per-step `$` echo lines. `WritableOp` is the bridge from
                    a leaf op to typed execution — `execute_via(executor) ->
                    Result<(), Self::Error>` returns the domain-specific
                    error type, and `op_ref() -> Op<'_>` produces the Op for
                    echo display. Implemented for `AccountOp` (Error =
                    AccountError), `ProfileOp` (Error = ProfileError), and
                    `FirewallOp` (Error = FirewallError). `Writer::run` is
                    generic over `WritableOp`, so one method handles all
                    three domains while preserving typed errors. LoginAsUser
                    is intentionally NOT a `WritableOp` impl (its return
                    type and stdio semantics are incompatible with the
                    trait's `execute_via`); the Writer's shell path calls
                    `executor.login(name)` directly. The LoginAsUser variant
                    exists in `AccountOp` solely for plan/echo rendering via
                    `Op::describe_via`. Impls: `MacosExecutor` (production;
                    argv knowledge lives in private `account_argv` /
                    inline firewall arms + literal-shell describe arms;
                    `execute_account` and `execute_firewall` spawn capturing
                    via `spawn_capturing` / `spawn_firewall`; the privileged-
                    fs path in `execute_firewall` uses
                    tempfile + `sudo mv` + `sudo chmod 0644` for atomic
                    writes to /etc/pf.anchors/* and /etc/pf.conf; `login`
                    spawns inheriting; the `Enable` arm specially treats
                    pfctl "already enabled" stderr as success — the plugin's
                    defensive pattern transcribed verbatim), `StubExecutor`
                    (records ops via `account_ops()` / `profile_ops()` /
                    `firewall_ops()` / `logins()`; per-op failure injection
                    via `fail_account_op(op, err)` / `fail_firewall_op(op,
                    err)`; blanket failure via `fail_account_blanket(code,
                    stderr)`; one-shot profile / firewall failure via
                    `fail_next_profile(err)` / `fail_next_firewall(err)`;
                    login exit code via `login_exit_code(n)`; in-memory
                    profile state simulation via `with_existing_profile` +
                    `has_profile` + `profile_state`; in-memory pf.conf state
                    via `with_pf_conf` reads through `read_pf_conf`;
                    per-name Create-content override via
                    `with_create_profile_content(name, content)` so a
                    create-flow test can simulate the
                    read_profile + parse + render_anchor path with
                    non-empty allowlists — production always writes
                    `default_profile_toml()`, the override lets a test
                    swap in a custom toml without rewriting the default),
                    `DryRunExecutor` (no-op execute / login; describe
                    delegates to MacosExecutor; `read_profile` returns
                    `default_profile_toml()` — the cycle-1 fact that
                    ProfileOp::Create would have written; `read_pf_conf`
                    returns the empty string — the plan focuses on what
                    tenant adds, not what's already there).
                    `AccountError { Spawn, NonZero { code, stderr } }`
                    mirrors the previous ExecError shape. `FirewallError {
                    Spawn, NonZero { code, stderr }, Fs { path, message },
                    RestoreFailed { path } }` parallels AccountError plus
                    two firewall-specific variants — `Fs` for tempfile/mv/
                    chmod failures (carries the path so the operator-facing
                    frame can name what failed) and `RestoreFailed` for the
                    recovery-of-recovery case (Reload failed → restore
                    fired → restore itself failed; renders with an em-dash
                    manual-recovery hint naming the backup path and the
                    `sudo cp` command to recover by hand).
src/profile.rs    — Domain data shapes + parsing for the profile-op
                    interface: `ProfileError` (wraps fs or injected failure
                    messages); `default_profile_toml()` (the
                    schema_version=1 + empty allowlist scaffolded at
                    create-time); `display_path_for(name)` (the literal-`~`
                    form used in plan / echo / error frames; the absolute
                    path lives privately inside MacosExecutor).
                    `Profile { schema_version, allowlist: Allowlist }` +
                    `Allowlist { runtime: Tier, install: Tier }` + `Tier {
                    hosts: Vec<String> }` are serde-derived value types
                    for the parsed profile. `parse(content) -> Result<Profile,
                    ProfileError>` pre-checks `schema_version` so a future
                    version bump produces the operator-readable refusal
                    `schema_version <N> not understood (this tenant supports
                    1)` instead of a low-level serde frame; structural
                    failures (missing sections, wrong types) fall through to
                    serde's error message, which the dispatcher rewraps in
                    the path-naming Reporter frame.
src/firewall.rs   — PF anchor + `/etc/pf.conf` line ops as pure functions;
                    the substrate's `MacosExecutor::execute_firewall` calls
                    them indirectly via the `FirewallOp::InstallAnchor.body`
                    / `UpdateConfig.content` payloads that the Writer
                    composes. Constants: `ANCHOR_DIR = "/etc/pf.anchors"`,
                    `PF_CONF = "/etc/pf.conf"`, `PF_CONF_BACKUP =
                    "/etc/pf.conf.tenant-backup"` (fixed-name; overwritten
                    on each invocation; deterministic recovery path). The
                    backup name carries the `tenant-` prefix so coexisting
                    host backup conventions (e.g. `pf.conf.bak`) stay
                    distinct. `tenant_anchor_name(name) -> "tenant-<name>"`
                    centralizes the anchor-name prefix (parallels
                    `accounts::tenant_share_group_name`); `tenant_anchor_path(name)`
                    composes the full absolute anchor file path.
                    `render_anchor(name, hosts) -> String` produces the
                    anchor body: header comment + table (backslash-continued
                    when populated, single-line `{ }` when empty) +
                    `pass out quick on lo0 user <name>` (loopback BEFORE
                    catchall — load-bearing for localhost reachability) +
                    `pass out quick proto tcp from any to <allowed> port 443
                    user <name>` + `block out quick proto { tcp udp } from
                    any to any user <name>`. Host order is preserved from
                    the input slice. `is_anchor_referenced(content, name) ->
                    bool` checks line-level (not substring — the bare
                    `anchor "X"` line is a substring of `load anchor "X"
                    from …`). `ensure_anchor_ref(content, name) -> String`
                    appends the two anchor lines for `tenant-<name>` if
                    absent (idempotent; never duplicates). `remove_anchor_ref(content,
                    name) -> String` strips both lines for `tenant-<name>`
                    while preserving unrelated content.
src/reporter.rs   — Operator-facing output: the layer between domain ops and
                    what the operator reads. Holds (stdout, stderr, verbose,
                    dry_run, executor); each verb has its own pre-exec /
                    post-exec methods that bake in the verb-specific phrasing
                    and handle mode/verbosity branching internally. Verb
                    methods:
                      create_starting(name, plan) / create_done(name, uid, gid)
                      destroy_starting(name, plan) / destroy_done(name)
                      orphan_group_starting(name, plan) /
                        orphan_group_done(name)
                      shell_starting(name, login_op)  — pair, no _done
                      destroy_absent(name)            — convergent noop
                    Plan parameter shape: `&[(Op<'_>, Option<&'static str>)]`
                    — `Op` for domain dispatch, the `Option<&'static str>`
                    slot for per-step annotations (`# on rollback` on the
                    create-side group rollback; `# on reload failure` on the
                    create-side PF recovery steps). The Reporter walks the
                    plan via `render_plan` (private), calling
                    `op.describe_via(self.executor)` per step. The per-step
                    echo method `step(op: Op<'_>)` emits `$ <rendered>` in
                    real+verbose only, lazily rendering via `Op::describe_via`.
                    Refusal methods (all to stderr, operator-friendly
                    framing): refuse_invalid_name, refuse_name_conflict,
                    refuse_not_a_tenant, refuse_system_account,
                    refuse_shell_absent, refuse_shell_not_a_tenant,
                    refuse_shell_system_account. Failure methods (also
                    stderr): create_group_failed, create_failed,
                    create_rollback_failed (em-dash-suffixed recovery hint),
                    create_profile_failed, create_firewall_failed,
                    destroy_failed, destroy_profile_failed,
                    destroy_firewall_failed, shell_failed.
src/main.rs       — composition root: MacosReader::new() + MacosExecutor;
                    tenant::run

tests/cli.rs           — every E2E test here; helpers run_with (default
                         NeverExecutor — panics on use, guards "should not
                         touch the host" paths) and run_with_exec
                         (caller-supplied StubExecutor for real-mode tests).
                         Behavioral tests assert on op shape via
                         `exec.account_ops()` / `exec.profile_ops()` /
                         `exec.firewall_ops()` / `exec.logins()`; display
                         tests assert byte-exact on stdout/stderr.
tests/macos_executor.rs — per-variant unit tests pinning the literal shell-
                         command shape that `MacosExecutor::describe_*`
                         produces. One test per AccountOp / ProfileOp /
                         FirewallOp variant; centralizes the argv contract
                         so a future tool swap (dseditgroup → dscl . -create;
                         pfctl → some future pf manager) moves exactly one
                         test per affected variant.
tests/profile_parse.rs — combinatorial coverage on `profile::parse`. Default
                         toml round-trip, populated runtime/install hosts
                         with order preservation, schema-version refusal,
                         missing sections, invalid TOML syntax.
tests/firewall_render.rs — combinatorial coverage on `firewall::render_anchor`.
                         Empty/populated table shape, backslash continuation,
                         host order preservation, loopback-pass-before-block
                         ordering, user-keyword scoping.
tests/firewall_conf.rs — combinatorial coverage on `firewall::ensure_anchor_ref`
                         / `remove_anchor_ref` / `is_anchor_referenced`.
                         Idempotent add/remove, partial-present cases,
                         unrelated-anchor non-interference, the
                         anchor-vs-load substring-distinction trap.
```

## Project doctrine

Things that are easy to violate and would matter:

- **Intent / mechanism split** — every user-facing emission is two-tier:
  a summary line (intent) and an optional indented detail block
  (mechanism, verbose only). Per-verb methods on `Reporter`
  (`create_starting` / `create_done`, `destroy_starting` / `destroy_done`,
  `orphan_group_starting` / `orphan_group_done`, `shell_starting`,
  plus refusal and failure methods) bake in the verb-specific phrasing
  and branch internally on (dry_run, verbose) to pick the right text.
  Each verb's `_starting` method takes a plan
  (`&[(Op<'_>, Option<&'static str>)]` — Op for domain dispatch, the
  optional annotation slot for `# on rollback` / `# on reload failure`
  -style notes); verbose mode renders the plan as a multi-line indented
  block. The Writer then emits per-step `$ <rendered>` echo lines via
  `Reporter::step` as each op executes — `step` is silent in dry-run
  and standard mode, active only in real+verbose. Conditional steps
  appear in the upfront plan but only echo if they actually run; the
  plan-vs-echo asymmetry is the operator-visible signal that a
  conditional step was skipped. The create plan's rollback line carries
  an `# on rollback` annotation (fires only on CreateTenantUser failure);
  the recovery sequence on PF Reload failure (RestoreConfigFromBackup
  → RemoveAnchor → Reload → FlushAnchor) carries `# on reload failure`
  on all four lines. Conditional steps appear in the plan unconditionally
  AND echo when they fire — the operator reads the plan as the algorithm,
  the echo as the trace. Interactive verbs like `shell` use a
  `_starting`-only pair (no `_done`) — the operator IS the shell after
  `login` returns, so a "Shelled into…" line after they exit would print
  to the host's terminal in a different session context. The "Shelling
  into" intent emits in standard mode too (not just verbose) so there's
  a project-side acknowledgement before the bare sudo prompt.
- **Intent (data) vs mechanism (substrate impl)** — the Writer expresses
  intent via `AccountOp` / `ProfileOp` / `FirewallOp` values; argv-
  construction and subprocess spawning live exclusively inside
  `MacosExecutor`'s `describe_*` / `execute_*` arms (plus the private
  `account_argv` helper and the inline pfctl/cp/rm/tee argv vectors in
  `execute_firewall`). The Writer never sees argv; tests assert on op
  identity (`exec.account_ops()[N] == AccountOp::CreateShareGroup
  { name: "dev".into(), gid: 600 }`, `exec.firewall_ops()[N] ==
  FirewallOp::FlushAnchor { name: "dev".into() }`), and the literal
  shell-command shape is pinned narrowly via `tests/macos_executor.rs`
  (one test per variant). Verbose-mode E2E stdout assertions in `cli.rs`
  still pin the operator-visible bytes end-to-end; the per-variant unit
  tests are the focused mechanism contract so a future swap (e.g.
  dseditgroup → dscl . -create) touches exactly one place per op.
- **ADT hierarchy: Op → AccountOp / ProfileOp / FirewallOp;
  WritableOp bridges back** — `Op<'a>` is the top-level enum wrapping
  `&AccountOp` / `&ProfileOp` / `&FirewallOp`. The three leaf ADTs have
  their own variants. `Op::describe_via(executor)` is the one place that
  matches on domain for display purposes — Reporter's plan rendering
  and per-step echo both flow through it. Execution goes the other
  direction: the `WritableOp` trait bridges from a leaf op back to a
  typed execution path, with `Self::Error` preserving the per-domain
  error type (`AccountError` for AccountOp, `ProfileError` for ProfileOp,
  `FirewallError` for FirewallOp). `Writer::run<O: WritableOp>` is
  generic over the trait; one method handles all three domains while
  keeping `CreateError::Group(AccountError)` / `Profile(ProfileError)`
  / `Firewall(FirewallError)` typed end-to-end. The asymmetry is
  honest: display is uniform (one Op enum for all ops), execution is
  typed (per-domain errors).
- **Sub-domains on the unified Executor, not separate traits per domain**
  — adding PF support in cycle 2 grew the existing `Executor` trait
  with `describe_firewall` / `execute_firewall` / `read_pf_conf` rather
  than introducing a `FirewallStore` trait alongside the existing
  account interface. The intent-vs-mechanism refactor (commit `42121a1`)
  collapsed an earlier `ProfileStore` into the same `Executor`; cycle
  2 followed the same pattern for firewall. A future sub-domain (sudoers,
  keychain) would land the same way: extend `Executor` with the new
  `describe_*` / `execute_*` pair plus any read carve-outs, add the
  ADT variant to `Op` and `WritableOp`, no new trait. The single
  `Executor` is the one test seam at the host boundary.
- **Dedicated carve-out methods for non-unit returns** — `Executor`
  has three side-execution methods (`execute_account` / `execute_profile`
  / `execute_firewall`) that return `Result<(), DomainError>`, plus
  three dedicated carve-out methods whose return types don't fit the
  unit shape: `login(name) -> Result<i32, AccountError>` (child shell's
  exit code), `read_profile(name) -> Result<String, ProfileError>`
  (file content), and `read_pf_conf() -> Result<String, FirewallError>`
  (file content). The carve-outs are NOT routed through `WritableOp` —
  they're called directly by the Writer (`self.executor.login(name)` /
  `self.executor.read_profile(name)` / `self.executor.read_pf_conf()`).
  When adding a future executor method, ask "does the return type fit
  `Result<(), E>`?" — if yes, model it as an ADT variant; if no
  (interactive return, content return), it's a dedicated method. Stub
  + DryRun impls cover all six methods.
- **Interactive verbs use `login`, not `execute_account`** — `execute_account`
  captures stdout/stderr so sysadminctl chatter is suppressed on success
  (good for batch verbs) and surfaces via `AccountError::NonZero` on
  failure; `login` inherits the parent's stdio so sudo can prompt and
  the launched login shell can drive the controlling terminal. Wiring
  `shell` through `execute_account` would silently swallow the shell
  session's output. `login` returns `Result<i32, AccountError>` — the
  i32 is the child's exit code for propagation, `AccountError` is
  reserved for spawn failures only. `LoginAsUser` is intentionally NOT
  a `WritableOp` impl; the LoginAsUser variant exists in `AccountOp`
  solely for plan/echo rendering via `Op::describe_via`. Tests pin
  both via StubExecutor: `fail_account_op(op, err)` /
  `fail_account_blanket(code, stderr)` for `execute_account`,
  `login_exit_code(n)` for `login`.
- **Probe via Executor, not Reader live re-read** — when a verb needs to
  re-check OS state mid-execution (destroy's LookupUserRecord residue
  probe is the canonical case), the probe is a regular substrate call
  (`Writer::run(&AccountOp::LookupUserRecord{..})` → `execute_account`
  under the hood) whose result drives a branch in the Writer
  (`Ok(())` means record present; `Err(AccountError::NonZero{..})`
  means the dscl probe found clean, cleanup-skip). The Reader trait
  stays snapshot-then-act: it's the in-memory view the dispatcher
  decided against. The Executor is the test seam; per-op overrides in
  StubExecutor (`fail_account_op`) let tests pin both probe outcomes.
  Don't add a "live re-read" method to Reader — it would confuse the
  snapshot doctrine.
- **No I/O in command logic** — verbs in `commands::dispatch` call
  Reporter's verb-named methods (`refuse_*`, `create_*_failed`,
  `destroy_*_failed`, `shell_failed`, `destroy_absent`) for all
  user-facing output. They never touch raw writers, check `cli.verbose`,
  or check `cli.dry_run` — mode branching lives inside Reporter. The
  `accounts::Writer` struct also calls Reporter's verb-named methods
  (`create_starting` / `create_done` / etc.) plus `Reporter::step` per
  substrate call; it owns intent + plan composition for its own actions
  but defers all mode/verbosity filtering to the Reporter.
- **Lexical → state-based check order** — `validate_name` runs before
  `check_conflict` (create) / `destroy_eligibility` (destroy) in dispatch.
  Cheaper failure first.
- **Convergent semantics for teardown verbs** — `destroy <name>` against
  an absent tenant is a successful noop, not an error. The state-based
  precheck (`destroy_eligibility`) returns `NotPresent` and dispatch
  emits the noop via `reporter.destroy_absent(name)` + exit 0. When the
  user is absent but a stale `<name>-tenant-share` group remains (e.g.
  a prior destroy that failed at the dseditgroup-delete step),
  `destroy_eligibility` returns `OrphanGroup` and dispatch calls
  `Writer::destroy_orphan_group` to converge — the operator's mental
  model of destroy ("after this, the host has no trace of <name>") is
  preserved across partial-failure recovery. The orphan-group path
  also runs the full PF teardown (5 ops including FlushAnchor) so
  partial-firewall state from a failed earlier create gets converged
  too; each PF step is idempotent (RemoveAnchor on missing file is a
  noop on the macOS side via `rm -f`; UpdateConfig with content equal
  to the existing pf.conf is a noop write; FlushAnchor on an unknown
  anchor is a noop). Same convergent contract applies to future
  teardown verbs.
- **`<name>-tenant-share` is the canonical group name; `tenant-<name>`
  is the canonical anchor name** — `accounts::tenant_share_group_name(name)`
  centralizes the group suffix; `firewall::tenant_anchor_name(name)`
  centralizes the anchor prefix. `check_conflict`, the create/destroy
  writers, the orphan-group convergence path, the user-facing Reporter
  methods, and the firewall line ops all derive their literal strings
  from these functions (and from `MacosExecutor::describe_account` /
  `describe_firewall` arms that produce the rendered shell-command
  lines). Tests pin the literal `dev-tenant-share` / `tenant-dev` text
  to catch any drift. Don't inline `format!("{name}-tenant-share")` or
  `format!("tenant-{name}")` at call sites — the centralization lets a
  future suffix/prefix change happen with one edit.
- **Decoupled UID/GID allocation** — `UidAllocator` reads `used_uids`,
  `GidAllocator` reads `used_gids`; the two spaces are disjoint and may
  legitimately diverge (e.g., UID 613, GID 600 on a host with prior
  tenants). Don't fuse them. The dseditgroup `-i <gid>` argument
  consumes the GID allocator's output; the sysadminctl `-UID <uid>
  -GID <gid>` argument consumes both. The
  `verbose_uid_and_gid_allocators_cross_over` test pins the divergence
  with a crossover stub — strongest defense against a regression that
  wires `-i` to `lowest_free_uid`.
- **Create partial-failure rollback / recovery posture** —
  `Writer::create_tenant` returns `CreateError::{Group(e), User(e),
  UserWithRollback{user, rollback}, Profile(e), Firewall(e)}`. The
  dispatcher routes each variant to a distinct Reporter method.
  `Group` (CreateShareGroup failed; no user touched) →
  `create_group_failed`. `User` (CreateTenantUser failed; rollback
  succeeded) → `create_failed`. `UserWithRollback` → TWO Reporter
  calls (`create_failed` first with the original error, then
  `create_rollback_failed` with the em-dash-suffixed `— host now has
  an orphan group; next 'tenant destroy <name>' will converge`).
  `Profile` (profile-write failed) → `create_profile_failed`. `Firewall`
  (any PF step failed, or the read_profile/parse/read_pf_conf compose-
  the-payload failed) → `create_firewall_failed`. Locked policy for
  the last two: user + group + profile stay present on Profile failure;
  user + group + profile + any partial PF state stay present on Firewall
  failure. Recovery in both cases is `tenant destroy <name>` — the
  Destroyable arm cleans user + group + profile, the PF teardown is
  idempotent (so partial-anchor state converges). On PF Reload failure
  specifically, the Writer runs a 4-step automatic recovery
  (RestoreConfigFromBackup → RemoveAnchor → Reload → FlushAnchor) BEFORE
  surfacing CreateError::Firewall(reload_err); the recovery is
  best-effort (post-restore steps ignore failures). Recovery-of-recovery
  (RestoreConfigFromBackup itself fails) surfaces as
  `CreateError::Firewall(FirewallError::RestoreFailed { path })` and
  renders with a manual-recovery hint naming the backup path and the
  `sudo cp` command.
- **PF anchor flush is load-bearing on every destroy path** —
  `pfctl -f /etc/pf.conf` reloads the parent ruleset but does NOT
  garbage-collect anchors whose `load anchor` directive has been
  removed. Without an explicit `pfctl -a tenant-<name> -F all`, the
  previous tenant's rules persist in kernel memory under an orphan
  anchor name and the next tenant getting the same UID silently
  inherits them. `FirewallOp::FlushAnchor` is the symmetric counter
  to `InstallAnchor`; it's the final step on both destroy paths
  (`destroy_tenant`, `destroy_orphan_group`) and on the create-side
  reload-failure recovery. Idempotent on the macOS side: flushing an
  empty/unknown anchor is a noop. Tests pin "FlushAnchor is the last
  firewall op on both destroy paths" AND "create's success path does
  NOT invoke FlushAnchor" (negative pin against accidental wiring that
  would wipe rules we just installed).
- **Tenant-floor guard on destroy** — `destroy_eligibility` refuses with
  `EX_USAGE 64` when the named account exists with a UID below
  `TENANT_UID_FLOOR` (`NotATenant`) or with no positive UID at all
  (`SystemAccount` — `nobody` and other negative-UID service accounts).
  The charset rail (`validate_name`) is the upstream guard; the floor is
  the downstream guard. Both are hard rails today; making them
  config-overridable with `--force` is on the roadmap.
- **Snapshot-then-act on the Reader** — `MacosReader::new()` queries dscl
  once at composition-root construction; every subsequent lookup is served
  from that in-memory snapshot. A second admin process mutating `/Users`
  between snapshot and `sudo sysadminctl …` could in principle cause us
  to destroy an account whose UID changed after we cleared it. Real-world
  exploitation requires concurrent root, which means the attacker can
  already destroy any account directly — so we accept the TOCTOU window
  today rather than re-snapshotting before each writer call. If a future
  use case widens the exposure (e.g. long-running daemon mode), the
  mitigation is to pass `-UID <verified>` to sysadminctl to bind the
  call to the UID the guard cleared.
- **Composition-root DI** — `tenant::run` takes `&dyn accounts::Reader`
  and `&dyn executor::Executor`. `main.rs` builds the prod impls
  (`MacosReader`, `MacosExecutor`); tests build their own (`StubReader`,
  `StubExecutor` / `NeverExecutor`). Writer is constructed inside `run`
  from the active Executor (`DryRunExecutor` swapped in when
  `cli.dry_run`), and Reporter is constructed with the same active
  Executor reference so it can render plan + echo lines lazily via
  `Op::describe_via`. The test seam stays at the Executor boundary
  while the Writer and Reporter are internal implementation details.
- **Exit codes** — `0` success (including destroy's convergent noop on
  an already-absent tenant AND the orphan-group convergence path); `64`
  (`EX_USAGE`, sysexits.h) for any user-input failure — validation,
  create-side conflict, destroy-side floor refusal (`NotATenant`),
  destroy-side system-account refusal (`SystemAccount`), shell-side
  refusals (absent / orphan-group / not-a-tenant / system-account); `74`
  (`EX_IOERR`) reserved for substrate execution failure (create-side
  any of the 12 ops including PF; destroy-side any of the 9 ops; shell-
  side `AccountError::Spawn` from `login`). Shell is the one verb that
  does NOT take an exit code from the set above on its success path —
  when `login` returns Ok, the child shell's exit code is propagated as
  tenant's own exit (clamped 0..=255), so `tenant shell dev` with `exit
  5` inside the session yields `tenant`-exit `5`. `1` is clap's default
  for parse errors (we don't override).
- **Acronym casing** — Rust convention treats acronyms as words: `Uid`
  not `UID`, `Macos` not `MacOS`. Methods are `lowest_free_uid`, struct
  is `UidAllocator`, `MacosReader`.
- **Clap flag scoping** — `-v / --verbose` and `--dry-run` are both
  `global = true` on `Cli` (accept either before or after the subcommand).
  Per-subcommand flags (`--strict`, `--json`, `--yes` per the seven-verb
  spec) stay scoped to their verb.

## Test discipline

E2E-first. The bulk of tests live in `tests/cli.rs` and drive through
`tenant::run` with a `StubReader`. Inline `#[cfg(test)] mod tests` blocks
are out of style on this project; standalone unit-test files need
explicit justification — `tests/macos_executor.rs` is the canonical
precedent (per-variant `describe_*` pins for the argv contract).
`tests/profile_parse.rs`, `tests/firewall_render.rs`, and
`tests/firewall_conf.rs` each carry the same justification: combinatorial
coverage on a pure function (`parse`, `render_anchor`, `ensure_anchor_ref`
/ `remove_anchor_ref` / `is_anchor_referenced`) whose call sites are
inside the writer and would otherwise need many overlapping E2E tests
to exercise the full matrix. Per-variant or per-shape unit testing is
the right tool when the function's state space is combinatorial; CLI
E2E remains the default for verb-level behavior.

Two helpers in cli.rs: `run_with(stub, args) -> (u8, String, String)`
wires a `NeverExecutor` (panics if any substrate method is called —
guards "should not touch the host" paths like dry-run / validation /
conflict). `run_with_exec(stub, &StubExecutor, args)` lets the test own
the executor for real-mode assertions on op shape / configured failure.
Both run the binary in-process and return exit code + stdout + stderr
as `String`s.

Behavioral assertions are on op identity (`exec.account_ops()` returns
`Vec<AccountOp>`; `exec.profile_ops()` returns `Vec<ProfileOp>`;
`exec.firewall_ops()` returns `Vec<FirewallOp>`; `exec.logins()` returns
`Vec<String>` of names passed to `login`). Display assertions are
byte-exact on rendered output (`stdout` / `stderr`). They pin the
user-facing contract; cosmetic message tweaks need test edits.

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

For manual macOS smoke (the production-side verification that the
test stubs can't cover — actual sysadminctl, dscl, pfctl behavior +
real network egress filtering): `bash .features/cycle2-smoke.sh
[tenant-name]` runs every command from the cycle-2 smoke plan in order
with self-documenting output. Designed for copy-paste-back review.

## The seven-verb spec (forward-looking design)

From the project's design consensus — verbs and their intended roles.
Shipping status is in the git log, not here.

| verb | role |
|---|---|
| `create <name>` | one-shot provisioning |
| `status <name>` | health summary; `--strict` for exit-code-on-drift |
| `shell <name>` | convergent recovery + login shell |
| `exec <name>` | convergent recovery + one command |
| `mode <name>` | session-scoped PF posture (strict / permissive) |
| `doctor` | host-level diagnostic + repair |
| `destroy <name>` | teardown |

Convention notes:
- `--strict` and `--json` are orthogonal axes on `status` (exit-code
  contract vs format).
- `--yes` is the universal confirmation-bypass on prompt-bearing verbs.
- `-v / --verbose` is the global mechanism-exposure flag (sudo invocations,
  UIDs, GIDs, suffixed group names, PF anchor names) — already implemented
  as `global = true` on the `Cli`. Verbose applies in dry-run too
  (Reporter precedence).

## Cross-references

- **Sandbox plugin (the original inspiration):**
  `/Users/Shared/sandbox/plugin-dev/claude-plugins/sandbox/`. A Python-CLI
  + skill that host-isolates Claude Code agents on macOS via per-agent
  user accounts, primary groups (named `<agent>-share`), PF anchors,
  login keychains, sudoers, and shared-root ACLs. The Rust `tenant` CLI
  is a generic agent-/Claude-Code-agnostic primitive for the
  user-account + primary-group + per-tenant-firewall layer; a future
  Claude-Code-specific layer would consume `tenant` and add
  Claude-specific phases on top. Load-bearing plugin files for
  prior-art lookups: `scripts/lib/phases/phase01_user.py` (user + group;
  "what argv shape works"), `scripts/lib/phases/phase_destroy.py`
  (dscl-residue mitigation), `scripts/lib/naming.py` (reserved-name
  set), `scripts/lib/allocation.py` (UID allocator shape),
  `scripts/lib/phases/phase02_pf.py` + `scripts/lib/pf.py` (PF anchor
  management — anchor template, ensure_anchor_ref/remove_anchor_ref
  line ops, pfctl orchestration; ported in cycle 2 with the
  load-bearing addition of explicit FlushAnchor that the plugin's
  destroy path lacks),
  `scripts/lib/install_mode.py` (session-scoped widening pattern —
  relevant for cycle 3's `mode` verb).
- **Go prototype (deprecated):** `/Users/plugin-dev/src/tenant/`. An
  intermediate iteration from before the Rust port; not being continued.
  Don't cross-reference for design decisions — the sandbox plugin is the
  source of truth for prior art, and the Rust port is the live codebase.
</content>
</invoke>