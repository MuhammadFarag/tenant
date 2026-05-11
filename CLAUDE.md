# tenant — Rust port of the macOS tenant-account CLI

A small CLI for provisioning macOS user accounts (and matching primary
groups) in a project-reserved UID range (≥600). `tenant create <name>`
inspects host account state, validates input, picks the next free UID,
and either renders the planned `sudo sysadminctl …` invocation
(`--dry-run`) or executes it (real mode). `tenant destroy <name>` is
the symmetric teardown verb (sysadminctl `-deleteUser`).

This crate is a Rust port of an earlier Go prototype (lives at
`/Users/plugin-dev/src/tenant/` for cross-reference). The Rust version
does not mirror the Go shape literally; it follows Rust idioms (clap derive,
composition-root DI, trait-object Reader, etc.) and has diverged where the
two languages' conventions diverge.

## Roadmap snapshot

Done:
- Project init, justfile + pre-commit gates (`fmt --check` + `clippy -D warnings`)
- `tenant create <name>` works in both dry-run and real mode (V1.5–V1.7)
- `tenant destroy <name>` works in both modes; convergent-noop on missing
  user (exit 0), refuses with `EX_USAGE 64` when the named account exists
  with a UID outside the tenant range — either a positive UID below
  `TENANT_UID_FLOOR` (system / human account, message names the floor) or
  no positive UID at all (system account like `nobody`, distinct message).
  Charset guard via `validate_name` reuse. No group cleanup yet — paired
  with explicit group lifecycle in the next vertical slice (see Open).
- `accounts::Reader` trait + `StubReader` (test) + `MacosReader` (dscl).
  Reader exposes `used_uids`, `has_user`, `has_group`, and `uid_for(name)`
  (added with destroy). `MacosReader` keeps `users` and `uid_by_name` as
  separate fields so service accounts with negative UIDs (`nobody`) still
  trip `has_user` even though they're filtered from the UID map.
- `accounts::Writer` trait + `MacosWriter` (sysadminctl-backed via Executor);
  `create_tenant` and `destroy_tenant` both follow the three-message bracket.
- `accounts::validate_name` (lexical: `[a-z][a-z0-9_-]{0,30}`, `EX_USAGE` on fail)
- `accounts::check_conflict` (state-based via Reader, `EX_USAGE` on fail)
- `accounts::destroy_eligibility` returns `Eligibility::{Destroyable,
  NotPresent, NotATenant { uid }, SystemAccount}`. `has_user` is the
  presence gate; `uid_for` carries the floor classification. The
  `SystemAccount` variant covers accounts present in the user listing
  with no positive UID (e.g. `nobody` at UID -2), filtered out of
  `uid_by_name` by `parse_uid_line` — without this variant the bug
  surface is `tenant destroy nobody` emitting a misleading "does not
  exist" noop instead of refusing.
- `allocation::UidAllocator::lowest_free_uid` (iterate from `TENANT_UID_FLOOR = 600`)
- `executor::Executor` trait + `SystemExecutor` (real, captures stderr) +
  `DryRunExecutor` (Ok-noop, swapped in at composition root when `--dry-run`) +
  `StubExecutor` (records calls; `failing` / `failing_with` for failure-path tests)
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
- E2E test suite in `tests/cli.rs` (reverse pyramid — no inline unit tests),
  43 cases via `run_with` / `run_with_exec` helpers + the
  `stub_with_tenant` / `stub_with_used_uids` setup helpers
- macOS-gated smoke test exercises real dscl

Open / likely next:
- **Vertical slice: explicit group lifecycle.** `create` today relies on
  sysadminctl's implicit "create matching group when `-GID` slot is free"
  side-effect; `destroy` doesn't touch the group at all. Pair the two:
  make `create` issue an explicit `dscl . -create /Groups/<name>` (or
  similar), and have `destroy` issue the matching `-delete`. Once that
  lands, the destroy path becomes truly symmetric with create.
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

## File map

```
src/lib.rs        — public API: pub fn run; declares modules; Cli + Verb + parse;
                    composition-root mode swap (DryRunExecutor when cli.dry_run)
src/commands.rs   — dispatch (the match on Verb) — no I/O, no cli.dry_run check;
                    emits via reporter.emit_err (failures, refusals) and
                    reporter.emit (convergent-noop success)
src/accounts.rs   — Reader + Writer traits; StubReader / MacosReader (dscl);
                    MacosWriter (argv build + Reporter emit + Executor delegation);
                    validate_name, check_conflict, destroy_eligibility
src/allocation.rs — UidAllocator + TENANT_UID_FLOOR
src/executor.rs   — Executor trait; SystemExecutor / DryRunExecutor / StubExecutor;
                    ExecError { Spawn, NonZero { code, stderr } }
src/messages.rs   — Message struct (summary / summary_verbose / dry_run_summary /
                    detail) + per-action factories (would_create_tenant /
                    creating_tenant / created_tenant for create; matching trio
                    for destroy plus destroy_absent, not_a_tenant, and
                    system_account_refusal)
src/reporter.rs   — Reporter holds (stdout, stderr, verbose, dry_run); methods
                    emit_err / emit (always-on-stdout) / emit_real_only /
                    emit_dry_only with mode-aware summary selection
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
  `summary_verbose` (real+verbose override; e.g. inlining UID), and
  `dry_run_summary` (dry-run override; "Would create…" vs "Creating…").
  Action factories live in `messages.rs`. The V1.7 pattern for a
  side-effecting verb is three bracketing messages: `would_<action>` for
  dry-only pre-exec, `<action>ing` (gerund) for real-verbose-only pre-exec
  intent + mechanism, `<action>ed` (past participle) for real-only post-exec
  confirmation. Each is emitted via the matching Reporter method
  (`emit_dry_only` / `emit_real_only`).
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
  the noop message + exit 0. The same applies to future teardown verbs.
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
- **Exit codes** — `0` success (including destroy's convergent noop on an
  already-absent tenant); `64` (`EX_USAGE`, sysexits.h) for any user-input
  failure — validation, create-side conflict, destroy-side floor refusal
  (`NotATenant`), destroy-side system-account refusal (`SystemAccount`);
  `74` (`EX_IOERR`) reserved for dscl / process-execution failure; `1` is
  clap's default for parse errors (we don't override).
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
| `destroy <name>` | teardown | ✓ (group cleanup deferred — see Roadmap) |

Convention notes:
- `--strict` and `--json` are orthogonal axes on `status` (exit-code
  contract vs format).
- `--yes` is the universal confirmation-bypass on prompt-bearing verbs.
- `-v / --verbose` is the global mechanism-exposure flag (sudo invocations,
  UIDs) — already implemented as `global = true` on the `Cli`.

## Cross-references

- Go reference project: `/Users/plugin-dev/src/tenant/`. Same domain,
  different idioms; useful for understanding intent but don't transliterate.
- The Go project's `.features/spec/` directory contains the design
  consensus the seven-verb spec came from (gitignored there; not duplicated
  here).
