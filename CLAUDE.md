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

## Roadmap snapshot

Done:
- Project init, justfile + pre-commit gates (`fmt --check` + `clippy -D warnings`)
- `tenant create <name>` works in both dry-run and real mode (V1.5–V1.7;
  Phase-3 expanded to two-argv group-first ordering — see Phase 3 entry)
- `tenant destroy <name>` works in both modes; convergent-noop on missing
  user (exit 0), refuses with `EX_USAGE 64` when the named account exists
  with a UID outside the tenant range — either a positive UID below
  `TENANT_UID_FLOOR` (system / human account, message names the floor) or
  no positive UID at all (system account like `nobody`, distinct message).
  Charset guard via `validate_name` reuse. Phase 3 added a 4th unconditional
  `dseditgroup -o delete` step and the `OrphanGroup` eligibility variant
  for convergent recovery from prior partial failures (see Phase 3 entry).
- Reserved-name blocklist (V1.8.2): `validate_name` refuses
  `{root, admin, staff, wheel, daemon, nobody, sudo}` with
  `NameError::Reserved` → `EX_USAGE`. Set copied verbatim from the
  sandbox plugin's `scripts/lib/naming.py`. Exact-match semantics —
  `rooty` / `wheelman` / `admins` pass the check. The lexical
  leading-letter rule already excludes the `_*` service-account
  namespace so no special handling for `_sandbox` etc.
- Destroy mechanism (V1.8): three-step `sysadminctl -deleteUser` →
  `dscl . -read /Users/<name>` (residue probe, no sudo) → conditional
  `sudo dscl . -delete /Users/<name>` (cleanup, only if probe shows the DS
  record still present). Belt-and-braces against the case where
  sysadminctl reports success but leaves a stale DS record that would
  block re-init — the mitigation was learned the hard way by the sandbox
  plugin (`/Users/Shared/sandbox/plugin-dev/claude-plugins/sandbox/`)
  that originally inspired this CLI. Probe-as-Executor-call (not a
  Reader live re-read) so the test seam stays at the Executor boundary.
  Standard-mode stdout is unchanged ("Destroyed tenant 'X'."); verbose
  shows the upfront pessimistic plan (3 indented argvs under
  "Destroying tenant 'X'.") followed by per-exec `$ <argv>` echo lines
  for what actually ran (the cleanup echo is absent when the probe
  finds DS clean — that asymmetry is the operator-visible signal that
  the cleanup was unnecessary).
- `accounts::Reader` trait + `StubReader` (test) + `MacosReader` (dscl).
  Reader exposes `used_uids`, `used_gids` (added Phase 3), `has_user`,
  `has_group`, and `uid_for(name)` (added with destroy). `MacosReader`
  keeps `users` and `uid_by_name` (and `groups` and `gid_by_name`) as
  separate fields so service accounts with negative UIDs (`nobody`) still
  trip `has_user` even though they're filtered from the ID maps. The
  GID-side parse uses `dscl . -list /Groups PrimaryGroupID` with the
  shared `parse_id_line` helper.
- `accounts::Writer` trait + `MacosWriter` (sysadminctl + dseditgroup,
  via Executor); `create_tenant` takes `(name, uid, gid, reporter)` and
  follows the bracketed Reporter discipline; `destroy_tenant` does too;
  `destroy_orphan_group` is the convergence-path verb added in Phase 3.
- `accounts::validate_name` (lexical: `[a-z][a-z0-9_-]{0,30}`, plus
  reserved-name blocklist `{root, admin, staff, wheel, daemon, nobody, sudo}`
  copied verbatim from the sandbox plugin's `naming.py`; `EX_USAGE` on fail).
  Blocklist runs after the charset checks so `Wheel` (capital W) still
  trips the more-specific `InvalidStart` feedback.
- `accounts::check_conflict` (state-based via Reader, `EX_USAGE` on fail)
- `accounts::destroy_eligibility` returns `Eligibility::{Destroyable,
  NotPresent, OrphanGroup, NotATenant { uid }, SystemAccount}`. `has_user`
  is the presence gate; `uid_for` carries the floor classification. The
  `SystemAccount` variant covers accounts present in the user listing
  with no positive UID (e.g. `nobody` at UID -2), filtered out of
  `uid_by_name` by `parse_id_line` — without this variant the bug
  surface is `tenant destroy nobody` emitting a misleading "does not
  exist" noop instead of refusing. The `OrphanGroup` variant (added in
  Phase 3) handles the convergent-recovery case where the tenant user
  is absent but `<name>-tenant-share` is still present.
- `allocation::UidAllocator::lowest_free_uid` and
  `allocation::GidAllocator::lowest_free_gid` (both iterate from
  `TENANT_UID_FLOOR = 600`; independent — Phase 3 explicitly does NOT
  force UID == GID)
- `executor::Executor` trait + `SystemExecutor` (real, captures stderr) +
  `DryRunExecutor` (Ok-noop, swapped in at composition root when `--dry-run`) +
  `StubExecutor` (records calls; `failing` / `failing_with` for global
  failure-path tests; `with_response_to` / `with_response_to_stderr` for
  per-argv-prefix overrides — needed when one specific call in a multi-call
  verb should fail while others succeed, e.g. destroy's dscl-read probe
  returning eDSRecordNotFound while sysadminctl succeeds)
- `Reporter` + `Message`: Reporter holds `(stdout, stderr, verbose, dry_run)`;
  Message holds `(summary, summary_verbose, dry_run_summary, detail)`; methods
  are `emit_err` (always-on-stderr), `emit` (always-on-stdout, added with
  destroy's noop message), `emit_real_only` (silent in dry), and `emit_dry_only`
  (silent in real). Verbose / dry-run mode selection is centralized in Reporter.
- Post-exec UX (V1.7): standard real mode emits one confirmation line
  ("Created tenant 'X'." / "Destroyed tenant 'X'."); verbose adds pre-exec
  intent + mechanism preview and (for create only) inlines UID into the
  confirmation — `destroyed_tenant` skips the UID since the dead account's
  UID isn't new info to the operator. Sysadminctl noise suppressed on
  success, surfaced via `ExecError::NonZero { code, stderr }` on failure.
- Multi-argv verbose UX (V1.8, destroy-only today): for verbs that issue
  more than one shell-out, `would_destroy_tenant` and `destroying_tenant`
  take `argvs: &[&[String]]` and render the full pessimistic plan as
  multiple indented lines under one summary. During real-mode execution,
  `running_argv` Messages emit `$ <argv>` echo lines per Executor call
  (verbose-only via `summary_verbose`). Operator's view: one upfront plan
  block + one execution-echo block; conditional commands appear in the
  plan but only show in the echo if they actually ran.
- Explicit group lifecycle (Phase 3): the primary group is named
  `<name>-tenant-share` (centralized via `accounts::tenant_share_group_name`),
  managed explicitly with `dseditgroup`. Create issues two argvs in
  group-first order — `sudo dseditgroup -o create -n . -i <gid>
  <name>-tenant-share` then `sudo sysadminctl -addUser <name> … -GID
  <gid>` — so the user's home directory chowns to the tenant-share
  group at creation time, not staff. Destroy appends an unconditional
  4th step (`sudo dseditgroup -o delete -n . <name>-tenant-share`); the
  pre-Phase-3 sysadminctl-cascade only caught implicit `<name>` groups
  and doesn't apply to the renamed group. UID and GID allocators are
  separate (`UidAllocator` reads `used_uids`, `GidAllocator` reads
  `used_gids`); they may legitimately produce different numbers
  (e.g. UID 601, GID 600). Conflict check refuses
  `<name>-tenant-share`-group existence (not bare `<name>`); a
  pre-existing bare-name group is now harmless. No
  dseditgroup-add-member step — the user's primary-group binding gives
  implicit member access on macOS.

  Partial-failure rollback: if dseditgroup-create succeeds but
  sysadminctl-addUser fails, the writer rolls back via
  `dseditgroup -o delete`. The granular `CreateError::{Group, User,
  UserWithRollback}` enum drives error rendering — the dispatcher
  picks `create_group_failed` for the dseditgroup case and
  `create_failed` for the sysadminctl case, with a second
  `rollback_failed` emission for the worst case (both fail). That
  second emission carries an em-dash-suffixed recovery hint pointing
  the operator at `tenant destroy <name>` — which converges via the
  Phase-3 `Eligibility::OrphanGroup` arm.

  Sandbox-plugin prior art: this is a clean-room port of just the
  phase-1 user+group machinery from
  `claude-plugins/sandbox/scripts/lib/phases/phase01_user.py` (argv
  shapes and tooling choices) and `phase_destroy.py` (cleanup ordering).
  The group-name suffix and dseditgroup convention come from there.
- E2E test suite in `tests/cli.rs` (reverse pyramid — no inline unit tests),
  62 cases via `run_with` / `run_with_exec` helpers + the
  `stub_with_tenant` / `stub_with_used_uids` setup helpers + the `argv`
  helper for multi-line argv assertions
- macOS-gated smoke test exercises real dscl

Open / likely next:
- **`status <name>`** — read-only verb; exercises the Reader without
  needing the Writer or Executor. Will likely surface `--strict` (exit
  code on drift) and `--json` (format) as orthogonal axes.
- **`doctor`** — host-level diagnostic. Multi-line default output will
  likely force `Vec<String>` generalization on `Message` fields.

Future / lower priority:
- **Config-overridable destroy guards.** Today the UID-floor and charset
  rails on `destroy` are hard-coded. Move thresholds to a config file when
  configurability becomes a real need; introduce `--force` to bypass guards
  explicitly at that point.
- **Destroy home-directory disposition flag.** Currently always uses the
  `sysadminctl -deleteUser` default (move the home directory to
  `/Users/Deleted Users/`). Add `--secure-erase` (shred) and `--keep-home`
  (retain) when a real use case shows up.
- **Destroy home-directory disclosure.** Today destroy emits no
  information about what happens to `/Users/<name>` — sysadminctl's
  default moves it to `/Users/Deleted Users/<name>` (recoverable via
  `mv` until that directory is emptied or the host is rebuilt), but the
  operator has no way to know that without reading `man sysadminctl`.
  Surface this at the dispatch layer: in dry-run / verbose, a pre-exec
  line stating where the home directory will go and whether the move is
  reversible; in real mode, a post-exec line pointing at the relocated
  path. Naturally pairs with the disposition flag entry above — once
  `--secure-erase` (irreversible) and `--keep-home` (no move) exist, the
  disclosure line varies by chosen disposition. Until then, the
  disclosure alone is worth adding because the recoverable-vs-not bit
  is the load-bearing piece of information for an operator about to
  destroy an account.
- **`ExecError::NonZero` stderr sanitization.** Today we echo captured
  sysadminctl stderr verbatim into our own stderr (via
  `ExecError::Display`). A hostile dscl / OD response could in principle
  embed ANSI escapes that mess with the operator's terminal. Low real
  exposure today (sysadminctl is trusted), but worth a strip-control-chars
  pass on `ExecError::stderr` if a future verb echoes more captured
  output, or if we ever shell out to tools that touch untrusted input.
- **Sudo-prompt explainer line.** Today sysadminctl triggers sudo's
  `Password:` prompt with no project-side context, so on a cold-cache
  invocation the operator sees a bare prompt and has to guess why. Emit
  one line just before invoking the writer that names the privileged
  action ("`tenant` needs sudo to provision/destroy a user via
  sysadminctl — you may be prompted for your password"), likely with a
  terminal color (yellow/cyan) to set it apart from regular output.
  Lives at the dispatch layer, gated on `stdout.is_terminal()` so it
  doesn't pollute scripted use. Should be silent in dry-run (no
  privileged call to explain).
- **Richer non-verbose default output.** Today standard real mode is
  one line per verb (`Created tenant 'X'.` / `Destroyed tenant 'X'.`).
  That's terse to the point of withholding load-bearing facts: an
  operator who just typed `tenant create devtest` doesn't see the
  assigned UID/GID, the home directory path, or the suffixed group
  name — they have to re-run with `-v` (already too late; the account
  is created) or grep dscl. Proposed default: still one summary line,
  but enriched — e.g., `Created tenant 'devtest' (UID 600, GID 600,
  group 'devtest-tenant-share', home /Users/devtest).`. The verbose
  mode would still add the mechanism preview + `$` echoes on top. The
  Message factory already supports this (the verbose-confirmation
  variant exists); the change is promoting some of that information
  into `summary`. Open questions: how much info before the line gets
  unwieldy; whether destroy should mirror the shape (less obviously
  useful since the account is gone — maybe just the home-dir
  disposition once that ships, per the disclosure entry above).
- **Pre-execution confirmation prompt.** Today `tenant create` and
  `tenant destroy` execute immediately — no "are you sure?" between
  invocation and side effect. Destroy in particular is a destructive
  verb; the operator should see the planned mechanism and accept it
  before sysadminctl runs. Proposed shape: show the verbose-style
  plan (the same one `--dry-run -v` emits today) then read a y/N
  confirmation from stdin. `--yes` (already in the seven-verb spec
  as the universal bypass) skips the prompt for scripted use; the
  prompt itself is gated on `stdin.is_terminal()` so non-interactive
  callers don't deadlock. Pairs naturally with the sudo-prompt
  explainer above — the confirmation prompt fires first, then sudo's
  password prompt, then exec. Implementation note: the prompt lives at
  the dispatch layer (after eligibility classification, before the
  writer call), reads from a `BufRead` handed in by the composition
  root (mirror of the `&mut dyn Write` Reporter pattern, so tests
  inject scripted input).

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

From the project's design consensus:

| verb | role | status |
|---|---|---|
| `create <name>` | one-shot provisioning | ✓ |
| `status <name>` | health summary; `--strict` for exit-code-on-drift | open |
| `shell <name>` | convergent recovery + login shell | open |
| `exec <name>` | convergent recovery + one command | open |
| `mode <name>` | session-scoped PF posture (strict / permissive) | open |
| `doctor` | host-level diagnostic + repair | open |
| `destroy <name>` | teardown | ✓ |

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
  is a clean-room rewrite of just **Phase 1** of the plugin's pipeline —
  the user-account primitive — intentionally agent-/Claude-Code-agnostic.
  Load-bearing files when designing tenant features: `scripts/lib/phases/phase01_user.py`
  (user + group creation; canonical answer to "what argv shape works"),
  `scripts/lib/phases/phase_destroy.py` (the dscl-residue mitigation
  V1.8 ports here), `scripts/lib/naming.py` (reserved-name set),
  `scripts/lib/allocation.py` (UID allocator shape).
- **Go prototype (deprecated):** `/Users/plugin-dev/src/tenant/`. An
  intermediate iteration from before the Rust port; not being continued.
  Don't cross-reference for design decisions — the sandbox plugin is the
  source of truth for prior art, and the Rust port is the live codebase.
  The Go project's `.features/spec/` directory contains the seven-verb
  spec text (gitignored there; not duplicated here) — only useful as a
  historical record of the spec's wording.
