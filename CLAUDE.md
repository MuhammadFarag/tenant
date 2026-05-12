# tenant — Rust port of the macOS tenant-account CLI

A small CLI for provisioning macOS user accounts and matching primary
groups (named `<name>-tenant-share`) in a project-reserved UID/GID range
(≥600). `tenant create <name>` inspects host account state, validates
input, picks the next free UID and GID independently, and either renders
the planned `sudo dseditgroup …` + `sudo sysadminctl …` invocations
(`--dry-run`) or executes them (real mode). `tenant destroy <name>` is
the symmetric teardown verb that runs sysadminctl `-deleteUser`, a dscl
residue probe + conditional cleanup, and a final `dseditgroup -o delete`.

This crate is a Rust port of an earlier Go prototype (lives at
`/Users/plugin-dev/src/tenant/` for cross-reference). The Rust version
does not mirror the Go shape literally; it follows Rust idioms (clap derive,
composition-root DI, trait-object Reader, etc.) and has diverged where the
two languages' conventions diverge.

## Scope

This file carries the stable doctrine and the file map below — facts
that describe what the code *currently does*, not what we plan to do
next. For the chronology of shipped versions, `git log --oneline`
walks the V<n> commits.

## File map

```
src/lib.rs        — public API: pub fn run; declares modules; Cli + Verb + parse;
                    composition-root mode swap (DryRunExecutor when cli.dry_run)
src/commands.rs   — dispatch (the match on Verb) — no I/O, no cli.dry_run check;
                    emits via reporter.emit_err (failures, refusals) and
                    reporter.emit (convergent-noop success). Create-side
                    matches CreateError::{Group, User, UserWithRollback, Profile};
                    destroy-side matches the 5-variant Eligibility and surfaces
                    DestroyError::{Account, Profile} via `surface_destroy_error`.
                    Shell-side reuses the same Eligibility classifier but
                    collapses NotPresent + OrphanGroup into a single
                    `shell_absent` refusal (the operator wants a shell; the
                    lingering group alone can't host one) and clamps the
                    child shell's i32 exit code into u8 for propagation.
src/accounts.rs   — Reader trait + StubReader / MacosReader (dscl);
                    Writer struct (composes AccountOp / ProfileOp values into
                    verb-level flows, hands them to the Executor); validate_name,
                    check_conflict, destroy_eligibility.
                    `tenant_share_group_name(name)` is the single source of
                    truth for the `<name>-tenant-share` suffix. `create_tenant`
                    builds CreateShareGroup → CreateTenantUser ops (with a
                    DeleteShareGroup rollback annotated `# on rollback`) plus
                    a ProfileOp::Create step; returns `CreateError`.
                    `destroy_tenant` builds DeleteTenantUser → LookupUserRecord
                    (probe; success gates the conditional DeleteUserRecord
                    cleanup) → DeleteShareGroup → ProfileOp::Delete; returns
                    `DestroyError`. `destroy_orphan_group` is the 2-op
                    convergence path (DeleteShareGroup + ProfileOp::Delete).
                    `shell_into_tenant` builds a LoginAsUser op solely for
                    plan rendering and dispatches through `Executor::login`,
                    returning the child shell's i32 exit code.
                    `parse_id_line` is the shared parser for both UID and
                    GID dscl listings (negative-ID filter + lowest-wins fold).
src/allocation.rs — UidAllocator + GidAllocator (both iterate from
                    TENANT_UID_FLOOR = 600; consult disjoint Reader maps,
                    independent values)
src/executor.rs   — Per-domain Op enums + unified Executor substrate.
                    `AccountOp` variants: CreateShareGroup, DeleteShareGroup,
                    CreateTenantUser, DeleteTenantUser, LookupUserRecord (the
                    dscl-read probe; success means record present),
                    DeleteUserRecord (the dscl-delete cleanup), LoginAsUser
                    (used only for `describe_account`; execution goes through
                    `login`). `ProfileOp` variants: Create, Delete.
                    `Executor` trait methods: `describe_account(op) -> String`
                    and `describe_profile(op) -> String` (operator-facing
                    display lines, used by both the upfront plan block and
                    the `$` echo lines); `execute_account(op) -> Result<(),
                    AccountError>` and `execute_profile(op) -> Result<(),
                    ProfileError>` (perform the side effect on this host);
                    `login(name) -> Result<i32, AccountError>` (interactive
                    path with inherited stdio and child exit code). Impls:
                    `MacosExecutor` (production; argv knowledge lives in the
                    private `account_argv` helper and the literal-shell
                    describe arms; `execute_account` spawns capturing,
                    `login` spawns inheriting), `StubExecutor` (records ops
                    via `account_ops()` / `profile_ops()` / `logins()`; per-op
                    failure injection via `fail_account_op(op, err)`;
                    blanket failure via `fail_account_blanket(code, stderr)`;
                    one-shot profile failure via `fail_next_profile(err)`;
                    login exit code via `login_exit_code(n)`; in-memory
                    profile state simulation via `with_existing_profile` +
                    `has_profile` + `profile_state`), `DryRunExecutor`
                    (no-op execute / login; describe delegates to
                    MacosExecutor). `AccountError { Spawn, NonZero { code,
                    stderr } }` mirrors the previous ExecError shape; the
                    `Display` impl prefixes "process exited with code N"
                    and appends captured stderr when present.
src/messages.rs   — Message struct (summary / summary_verbose / dry_run_summary /
                    detail) + per-action factories. `PlanStep<'a>` carries a
                    pre-rendered display line + optional `# <note>`
                    annotation; the writer builds plans via `PlanStep::plain`
                    / `PlanStep::annotated` using the executor's `describe_*`
                    output. `render_plan` joins steps with two-space
                    indentation and appends the annotation suffix when set.
                    Create trio (would_create_tenant / creating_tenant /
                    created_tenant) — created_tenant inlines UID + GID in
                    verbose. Destroy trio (would_destroy_tenant /
                    destroying_tenant / destroyed_tenant). Orphan-group trio
                    (would_destroy_orphan_group / destroying_orphan_group /
                    destroyed_orphan_group) — standard-mode framing names the
                    tenant; verbose adds the literal group name. `running`
                    is the unified per-step echo factory (`$ <rendered>`),
                    used for both real shell-outs and synthetic profile
                    steps. Error factories: `create_group_failed`,
                    `create_failed`, `create_profile_failed`,
                    `rollback_failed` (em-dash-suffixed recovery hint),
                    `destroy_failed`, `destroy_profile_failed`, plus
                    destroy_absent, not_a_tenant, system_account_refusal,
                    invalid_name, name_conflict. Shell pair
                    (would_shell_into_tenant / shelling_into_tenant) — pair
                    not trio because there's no post-exec confirmation (the
                    operator IS the shell after login returns). The
                    "Shelling into" intent line lives in `summary` (not
                    `summary_verbose`) so it emits in standard mode too —
                    without a post-exec line to do the talking, standard-mode
                    silence would leave the operator looking at a bare sudo
                    prompt with no project-side context. Shell refusals:
                    shell_absent (collapsed NotPresent+OrphanGroup),
                    shell_not_a_tenant, shell_system_account_refusal,
                    shell_failed (spawn failure).
src/profile.rs    — Domain data shapes for the profile-op interface that
                    Executor owns: `ProfileError` (wraps fs or injected
                    failure messages); `default_profile_toml()` (the
                    schema_version=1 + empty allowlist scaffolded at
                    create-time); `display_path_for(name)` (the literal-`~`
                    form used in plan / echo / error frames; the absolute
                    path lives privately inside MacosExecutor).
src/reporter.rs   — Reporter holds (stdout, stderr, verbose, dry_run); methods
                    emit_err / emit (always-on-stdout) / emit_real_only /
                    emit_dry_only with mode-aware summary selection.
                    `summary_verbose` applies in both real+verbose AND
                    dry-run+verbose (verbose-intent honors the operator's
                    `-v` regardless of mode); `dry_run_summary` is the
                    dry-run-specific override when no verbose override exists.
src/main.rs       — composition root: MacosReader::new() + MacosExecutor; tenant::run

tests/cli.rs           — every E2E test here; helpers run_with (default
                         NeverExecutor — panics on use, guards "should not
                         touch the host" paths) and run_with_exec
                         (caller-supplied StubExecutor for real-mode tests).
                         Behavioral tests assert on op shape via
                         `exec.account_ops()` / `exec.profile_ops()` /
                         `exec.logins()`; display tests assert byte-exact
                         on stdout/stderr.
tests/macos_executor.rs — per-variant unit tests pinning the literal shell-
                         command shape that `MacosExecutor::describe_*`
                         produces. One test per AccountOp / ProfileOp
                         variant; centralizes the argv contract so a future
                         tool swap (dseditgroup → dscl . -create) moves
                         exactly one test per affected variant.
```

## Project doctrine

Things that are easy to violate and would matter:

- **Intent / mechanism split** — every user-facing emission has a "summary"
  (intent) and an optional "detail" (mechanism — the rendered shell-style
  line, verbose only). Reporter picks the right summary for the current
  mode/verbosity from up to four Message fields: `summary` (default),
  `summary_verbose` (verbose override — applies in BOTH real+verbose AND
  dry-run+verbose; e.g. inlining UID+GID or naming the suffixed group),
  and `dry_run_summary` (dry-run-specific override when no verbose
  override exists; "Would create…" vs "Creating…"). Verbose intent
  wins over mode-specific framing — the operator's `-v` request applies
  regardless of `--dry-run`. Action factories live in `messages.rs`.
  The pattern for a side-effecting verb is three bracketing
  messages: `would_<action>` for dry-only pre-exec, `<action>ing`
  (gerund) for real-verbose-only pre-exec intent + mechanism,
  `<action>ed` (past participle) for real-only post-exec confirmation.
  Each is emitted via the matching Reporter method (`emit_dry_only` /
  `emit_real_only`). For verbs that issue more than one substrate call
  (destroy was the first; create grew to four steps in cycle 1), the
  `would_<action>` / `<action>ing` factories take `&[PlanStep<'_>]`
  and render the full pessimistic plan as multi-line detail; `running`
  Messages then emit `$ <rendered>` echo lines per substrate call inside
  the Writer. Conditional steps appear in the upfront plan but only echo
  if they actually run — the plan-vs-echo asymmetry is the operator-
  visible signal that a conditional step was skipped. The create plan's
  rollback line carries an `# on rollback` annotation in the plan
  (rolls back only on CreateTenantUser failure); the rollback also
  appears in the echo block when it actually fires (e.g. on partial-
  failure paths). The annotation channel is general — cycle 2's PF
  restore-on-reload-failure step will share the same shape.
  Interactive verbs like `shell` use a 2-message pair (no post-exec
  past-participle) — the operator IS the shell after `login` returns,
  so a "Shelled into…" line after they exit would print to the host's
  terminal in a different session context. The "Shelling into" intent
  populates `summary` (not `summary_verbose`) so it shows in standard
  mode too — there's no post-exec line to acknowledge the action
  otherwise.
- **Intent (data) vs mechanism (substrate impl)** — the Writer expresses
  intent via `AccountOp` / `ProfileOp` values; argv-construction and
  subprocess spawning live exclusively inside `MacosExecutor`'s
  `describe_account` / `execute_account` (plus the private `account_argv`
  helper). No `build_*_argv` helpers at the Writer level — they were
  removed when the intent/mechanism split landed. The Writer never sees
  argv; tests assert on op identity (`exec.account_ops()[N] ==
  AccountOp::CreateShareGroup { name: "dev".into(), gid: 600 }`), and the
  literal shell-command shape is pinned narrowly via
  `tests/macos_executor.rs` (one test per variant). Verbose-mode E2E
  stdout assertions in `cli.rs` still pin the operator-visible bytes
  end-to-end; the per-variant unit tests are the focused mechanism
  contract so a future swap (e.g. dseditgroup → dscl . -create) touches
  exactly one place per op.
- **Interactive verbs use `login`, not `execute_account`** — `Executor`
  has two execution substitution points: `execute_account` captures
  stdout/stderr so sysadminctl chatter is suppressed on success (good
  for batch verbs) and surfaces via `AccountError::NonZero` on failure;
  `login` inherits the parent's stdio so sudo can prompt and the launched
  login shell can drive the controlling terminal. Wiring `shell` through
  `execute_account` would silently swallow the shell session's output.
  `login` returns `Result<i32, AccountError>` — the i32 is the child's
  exit code for propagation, `AccountError` is reserved for spawn
  failures only. Tests pin both via StubExecutor: `fail_account_op(op,
  err)` / `fail_account_blanket(code, stderr)` for `execute_account`,
  `login_exit_code(n)` for `login`.
- **Probe via Executor, not Reader live re-read** — when a verb needs to
  re-check OS state mid-execution (destroy's LookupUserRecord residue
  probe is the canonical case), the probe is a regular substrate call
  (`execute_account(&AccountOp::LookupUserRecord{..})`) whose result
  drives a branch in the Writer (`Ok(())` means record present;
  `Err(AccountError::NonZero{..})` means the dscl probe found clean,
  cleanup-skip). The Reader trait stays snapshot-then-act: it's the
  in-memory view the dispatcher decided against. The Executor is the
  test seam; per-op overrides in StubExecutor (`fail_account_op`) let
  tests pin both probe outcomes. Don't add a "live re-read" method to
  Reader — it would confuse the snapshot doctrine.
- **No I/O in command logic** — verbs receive `&mut Reporter`, emit via
  `reporter.emit_err(...)` (failure paths) or `reporter.emit(...)`
  (mode-neutral success messages like destroy's convergent-noop), return
  `u8`. They never touch raw writers, check `cli.verbose`, or check
  `cli.dry_run`. The `accounts::Writer` struct also emits via Reporter —
  it's explicitly an I/O layer (it dispatches substrate calls and renders
  plan/echo) and owns intent + mechanism rendering for its own actions,
  using `emit_real_only` / `emit_dry_only` to scope output to the
  appropriate mode.
- **Lexical → state-based check order** — `validate_name` runs before
  `check_conflict` (create) / `destroy_eligibility` (destroy) in dispatch.
  Cheaper failure first.
- **Convergent semantics for teardown verbs** — `destroy <name>` against
  an absent tenant is a successful noop, not an error. The state-based
  precheck (`destroy_eligibility`) returns `NotPresent` and dispatch emits
  the noop message + exit 0. When the user is absent but a stale
  `<name>-tenant-share` group remains (e.g. a prior destroy that failed
  at the dseditgroup-delete step), `destroy_eligibility` returns
  `OrphanGroup` and dispatch calls `Writer::destroy_orphan_group` to
  converge — the operator's mental model of destroy ("after this, the
  host has no trace of <name>") is preserved across partial-failure
  recovery. Same convergent contract applies to future teardown verbs.
- **`<name>-tenant-share` is the canonical group name** —
  `accounts::tenant_share_group_name(name)` is the single source of
  truth for the suffix. `check_conflict`, `Writer::create_tenant`,
  `Writer::destroy_tenant`, `Writer::destroy_orphan_group`,
  `destroy_eligibility::OrphanGroup`, and the user-facing
  `name_conflict` / `create_group_failed` / `rollback_failed` /
  orphan-group factories all derive the literal string from this
  function (and from `MacosExecutor::describe_account` arms that
  produce the rendered shell-command lines). Tests pin the literal
  `dev-tenant-share` text to catch any drift. Don't inline
  `format!("{name}-tenant-share")` at call sites — the centralization
  lets a future suffix change happen with one edit.
- **Decoupled UID/GID allocation** — `UidAllocator` reads `used_uids`,
  `GidAllocator` reads `used_gids`; the two spaces are disjoint and may
  legitimately diverge (e.g., UID 613, GID 600 on a host with prior
  tenants). Don't fuse them. The dseditgroup `-i <gid>` argument
  consumes the GID allocator's output; the sysadminctl `-UID <uid>
  -GID <gid>` argument consumes both. The `verbose_uid_and_gid_allocators_cross_over`
  test pins the divergence with a crossover stub — strongest defense
  against a regression that wires `-i` to `lowest_free_uid`.
- **Create partial-failure rollback** — `Writer::create_tenant`
  returns `CreateError::{Group(e), User(e), UserWithRollback{user,
  rollback}, Profile(e)}`. The dispatcher renders distinct messages per
  variant — `create_group_failed` for `Group` (no user touched),
  `create_failed` for `User` (rollback succeeded), TWO emit_err calls
  for `UserWithRollback` (the original failure first, then
  `rollback_failed` with the em-dash-suffixed `— host now has an orphan
  group; next 'tenant destroy <name>' will converge`), and
  `create_profile_failed` for `Profile` (locked policy: user + group
  stay on the host; recovery is `tenant destroy <name>` — the
  Destroyable arm cleans the user + group, profile-rm is a noop on
  the missing-profile case). The recovery story is load-bearing UX:
  the operator doesn't need to read source to know what to do next.
  `OrphanGroup` eligibility is the corresponding convergence path.
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
  `cli.dry_run`), so the test seam stays at the Executor boundary while
  the Writer is an internal implementation detail. The Executor absorbs
  what used to be a separate ProfileStore seam — one trait carries both
  account-domain and profile-domain methods so the composition root has
  exactly one substrate to wire.
- **Exit codes** — `0` success (including destroy's convergent noop on
  an already-absent tenant AND the orphan-group convergence path); `64`
  (`EX_USAGE`, sysexits.h) for any user-input failure — validation,
  create-side conflict, destroy-side floor refusal (`NotATenant`),
  destroy-side system-account refusal (`SystemAccount`), shell-side
  refusals (absent / orphan-group / not-a-tenant / system-account); `74`
  (`EX_IOERR`) reserved for substrate execution failure (create-side
  CreateShareGroup, CreateTenantUser, rollback, and profile-write paths
  all map here; destroy-side any of the five steps; shell-side
  `AccountError::Spawn` from `login`). Shell is the one verb that does
  NOT take an exit code from the set above on its success path — when
  `login` returns Ok, the child shell's exit code is propagated as
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
explicit justification — `tests/macos_executor.rs` is the one in-tree
example, justified by per-variant combinatorial coverage of
`MacosExecutor::describe_*` that's awkward via the CLI surface.

Two helpers in cli.rs: `run_with(stub, args) -> (u8, String, String)`
wires a `NeverExecutor` (panics if any substrate method is called —
guards "should not touch the host" paths like dry-run / validation /
conflict). `run_with_exec(stub, &StubExecutor, args)` lets the test own
the executor for real-mode assertions on op shape / configured failure.
Both run the binary in-process and return exit code + stdout + stderr
as `String`s.

Behavioral assertions are on op identity (`exec.account_ops()` returns
`Vec<AccountOp>`; `exec.profile_ops()` returns `Vec<ProfileOp>`;
`exec.logins()` returns `Vec<String>` of names passed to `login`).
Display assertions are byte-exact on rendered output (`stdout` /
`stderr`). They pin the user-facing contract; cosmetic message tweaks
need test edits.

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
  UIDs, GIDs, suffixed group names) — already implemented as `global = true`
  on the `Cli`. Verbose applies in dry-run too (Reporter precedence).

## Cross-references

- **Sandbox plugin (the original inspiration):**
  `/Users/Shared/sandbox/plugin-dev/claude-plugins/sandbox/`. A Python-CLI
  + skill that host-isolates Claude Code agents on macOS via per-agent
  user accounts, primary groups (named `<agent>-share`), PF anchors,
  login keychains, sudoers, and shared-root ACLs. The Rust `tenant` CLI
  is a generic agent-/Claude-Code-agnostic primitive for the
  user-account + primary-group layer; a future Claude-Code-specific
  layer would consume `tenant` and add Claude-specific phases on top.
  Load-bearing plugin files for prior-art lookups:
  `scripts/lib/phases/phase01_user.py` (user + group; "what argv
  shape works"), `scripts/lib/phases/phase_destroy.py` (dscl-residue
  mitigation), `scripts/lib/naming.py` (reserved-name set),
  `scripts/lib/allocation.py` (UID allocator shape),
  `scripts/lib/phases/phase02_pf.py` + `scripts/lib/pf.py` (PF
  anchor management — relevant for the next-phase build).
- **Go prototype (deprecated):** `/Users/plugin-dev/src/tenant/`. An
  intermediate iteration from before the Rust port; not being continued.
  Don't cross-reference for design decisions — the sandbox plugin is the
  source of truth for prior art, and the Rust port is the live codebase.
