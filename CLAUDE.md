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
                    matches CreateError::{Group, User, UserWithRollback};
                    destroy-side matches the 5-variant Eligibility.
src/accounts.rs   — Reader + Writer traits; StubReader / MacosReader (dscl);
                    MacosWriter (argv build + Reporter emit + Executor delegation);
                    validate_name, check_conflict, destroy_eligibility.
                    `tenant_share_group_name(name)` is the single source of
                    truth for the `<name>-tenant-share` suffix. `create_tenant`
                    issues 2 argvs (build_dseditgroup_create_argv,
                    build_create_argv) plus the rollback argv on
                    sysadminctl failure (build_dseditgroup_delete_argv);
                    returns `CreateError`. `destroy_tenant` issues 4 argvs:
                    build_destroy_sysadminctl_argv, build_dscl_read_user_argv
                    (probe), build_dscl_delete_user_argv (conditional
                    cleanup), build_dseditgroup_delete_argv (Phase-3
                    unconditional group cleanup). `destroy_orphan_group`
                    issues just the dseditgroup-delete (convergence path).
                    `parse_id_line` is the shared parser for both UID and
                    GID dscl listings (negative-ID filter + lowest-wins fold).
src/allocation.rs — UidAllocator + GidAllocator (both iterate from
                    TENANT_UID_FLOOR = 600; consult disjoint Reader maps,
                    independent values)
src/executor.rs   — Executor trait; SystemExecutor / DryRunExecutor / StubExecutor;
                    ExecError { Spawn, NonZero { code, stderr } }; StubExecutor
                    has `with_response_to(prefix, code)` for per-call overrides
src/messages.rs   — Message struct (summary / summary_verbose / dry_run_summary /
                    detail) + per-action factories. Create trio
                    (would_create_tenant / creating_tenant) takes group_argv,
                    user_argv, rollback_argv and renders a 3-line plan via
                    `render_create_plan` (3rd line annotated `# on rollback`);
                    `created_tenant(name, uid, gid)` inlines both IDs in
                    verbose. Destroy trio (would_destroy_tenant /
                    destroying_tenant) takes `argvs: &[&[String]]` and
                    renders multi-line plans via `render_plan`. Orphan-group
                    trio (would_destroy_orphan_group / destroying_orphan_group /
                    destroyed_orphan_group) takes a single argv;
                    standard-mode framing names the tenant, verbose adds
                    the literal group name. `running_argv` is the per-exec
                    echo factory. `create_group_failed` (dseditgroup-create
                    failure), `create_failed` (sysadminctl failure),
                    `rollback_failed` (em-dash-suffixed recovery hint),
                    `destroy_failed`, plus destroy_absent, not_a_tenant,
                    system_account_refusal, invalid_name, name_conflict.
src/reporter.rs   — Reporter holds (stdout, stderr, verbose, dry_run); methods
                    emit_err / emit (always-on-stdout) / emit_real_only /
                    emit_dry_only with mode-aware summary selection.
                    `summary_verbose` applies in both real+verbose AND
                    dry-run+verbose (verbose-intent honors the operator's
                    `-v` regardless of mode); `dry_run_summary` is the
                    dry-run-specific override when no verbose override exists.
src/main.rs       — composition root: MacosReader::new() + SystemExecutor; tenant::run

tests/cli.rs      — every test here; helpers run_with (default NeverExecutor —
                    panics on use, guards "should not exec" paths) and
                    run_with_exec (caller-supplied StubExecutor for real-mode tests)
```

## Project doctrine

Things that are easy to violate and would matter:

- **Intent / mechanism split** — every user-facing emission has a "summary"
  (intent) and an optional "detail" (mechanism — the `sudo sysadminctl …`
  argv, verbose only). Reporter picks the right summary for the current
  mode/verbosity from up to four Message fields: `summary` (default),
  `summary_verbose` (verbose override — applies in BOTH real+verbose AND
  dry-run+verbose; e.g. inlining UID+GID or naming the suffixed group),
  and `dry_run_summary` (dry-run-specific override when no verbose
  override exists; "Would create…" vs "Creating…"). Verbose intent
  wins over mode-specific framing — the operator's `-v` request applies
  regardless of `--dry-run`. Action factories live in `messages.rs`.
  The V1.7 pattern for a side-effecting verb is three bracketing
  messages: `would_<action>` for dry-only pre-exec, `<action>ing`
  (gerund) for real-verbose-only pre-exec intent + mechanism,
  `<action>ed` (past participle) for real-only post-exec confirmation.
  Each is emitted via the matching Reporter method (`emit_dry_only` /
  `emit_real_only`). For verbs that issue more than one shell-out (V1.8
  destroy was the first; Phase-3 create is the second), the
  `would_<action>` / `<action>ing` factories take an argv tuple or
  `argvs: &[&[String]]` and render the full pessimistic plan as
  multi-line detail; `running_argv` Messages then emit `$ <argv>` echo
  lines per Executor call inside the Writer. Conditional argvs appear in
  the upfront plan but only echo if they actually run — the plan-vs-echo
  asymmetry is the operator-visible signal that a conditional step was
  skipped. Phase-3's create plan adds a special case: the 3rd line is
  annotated `  # on rollback` to flag it as conditional in the plan
  (rolls back only on sysadminctl failure); the rollback also appears in
  the echo block when it actually fires (e.g. on partial-failure paths).
- **Probe via Executor, not Reader live re-read** — when a verb needs to
  re-check OS state mid-execution (V1.8 destroy's dscl-read residue probe
  is the canonical case), the probe is a regular Executor call whose
  exit code drives a branch in the Writer. The Reader trait stays
  snapshot-then-act: it's the in-memory view the dispatcher decided
  against. The Executor is the test seam; per-call overrides in
  StubExecutor (`with_response_to`) let tests pin both probe outcomes.
  Don't add a "live re-read" method to Reader — it would confuse the
  snapshot doctrine.
- **No I/O in command logic** — verbs receive `&mut Reporter`, emit via
  `reporter.emit_err(...)` (failure paths) or `reporter.emit(...)`
  (mode-neutral success messages like destroy's convergent-noop), return
  `u8`. They never touch raw writers, check `cli.verbose`, or check
  `cli.dry_run`. Writers (`accounts::Writer`) also emit via Reporter —
  they're explicitly an I/O layer (they shell out) and own intent +
  mechanism rendering for their own actions, using `emit_real_only` /
  `emit_dry_only` to scope output to the appropriate mode.
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
  truth for the suffix. `check_conflict`, `MacosWriter::create_tenant`,
  `MacosWriter::destroy_tenant`, `MacosWriter::destroy_orphan_group`,
  `destroy_eligibility::OrphanGroup`, and the user-facing
  `name_conflict` / `create_group_failed` / `rollback_failed` /
  orphan-group factories all derive the literal string from this
  function. Tests pin the literal `dev-tenant-share` text to catch any
  drift. Don't inline `format!("{name}-tenant-share")` at call sites —
  the centralization lets a future suffix change happen with one edit.
- **Decoupled UID/GID allocation** — `UidAllocator` reads `used_uids`,
  `GidAllocator` reads `used_gids`; the two spaces are disjoint and may
  legitimately diverge (e.g., UID 613, GID 600 on a host with prior
  tenants). Don't fuse them. The dseditgroup `-i <gid>` argument
  consumes the GID allocator's output; the sysadminctl `-UID <uid>
  -GID <gid>` argument consumes both. The `verbose_uid_and_gid_allocators_cross_over`
  test pins the divergence with a crossover stub — strongest defense
  against a regression that wires `-i` to `lowest_free_uid`.
- **Create partial-failure rollback** — `MacosWriter::create_tenant`
  returns `CreateError::{Group(e), User(e), UserWithRollback{user,
  rollback}}`. The dispatcher renders distinct messages per variant —
  `create_group_failed` for `Group` (no user touched), `create_failed`
  for `User` (rollback succeeded), and TWO emit_err calls for
  `UserWithRollback` (the original failure first, then `rollback_failed`
  with the em-dash-suffixed `— host now has an orphan group; next
  'tenant destroy <name>' will converge`). The recovery story is
  load-bearing UX: the operator doesn't need to read source to know
  what to do next. `OrphanGroup` eligibility (cycle 5) is the
  corresponding convergence path.
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
  (`MacosReader`, `SystemExecutor`); tests build their own (`StubReader`,
  `StubExecutor` / `NeverExecutor`). Writer is constructed inside `run`
  from the active Executor (DryRunExecutor swapped in when `cli.dry_run`),
  so the test seam stays at the Executor boundary while the Writer is an
  internal implementation detail.
- **Exit codes** — `0` success (including destroy's convergent noop on
  an already-absent tenant AND the orphan-group convergence path); `64`
  (`EX_USAGE`, sysexits.h) for any user-input failure — validation,
  create-side conflict, destroy-side floor refusal (`NotATenant`),
  destroy-side system-account refusal (`SystemAccount`); `74`
  (`EX_IOERR`) reserved for dscl / dseditgroup / sysadminctl / process-
  execution failure (create-side dseditgroup-create, sysadminctl-addUser,
  and rollback-failure paths all map here; destroy-side any of the
  four steps); `1` is clap's default for parse errors (we don't override).
- **Acronym casing** — Rust convention treats acronyms as words: `Uid`
  not `UID`, `Macos` not `MacOS`. Methods are `lowest_free_uid`, struct
  is `UidAllocator`, `MacosReader`.
- **Clap flag scoping** — `-v / --verbose` and `--dry-run` are both
  `global = true` on `Cli` (accept either before or after the subcommand).
  Per-subcommand flags (`--strict`, `--json`, `--yes` per the seven-verb
  spec) stay scoped to their verb.

## Test discipline

E2E-only. All tests live in `tests/cli.rs` and drive through `tenant::run`
with a `StubReader`. Inline `#[cfg(test)] mod tests` blocks are out of style
on this project; unit tests need explicit justification (combinatorial
coverage that's awkward via the CLI surface, etc.) — the bar is high.

Two helpers: `run_with(stub, args) -> (u8, String, String)` wires a
`NeverExecutor` (panics if exec is reached — guards "should not touch the
host" paths like dry-run / validation / conflict). `run_with_exec(stub,
&StubExecutor, args)` lets the test own the executor for real-mode
assertions on argv / configured failure. Both run the binary in-process
and return exit code + stdout + stderr as `String`s.

Byte-exact assertions on rendered output are the norm. They pin the
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
