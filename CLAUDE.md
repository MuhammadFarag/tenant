# tenant — Rust port of the macOS tenant-account CLI

A small CLI for provisioning macOS user accounts (and matching primary
groups) in a project-reserved UID range (≥600). `tenant create <name>`
inspects host account state, validates input, picks the next free UID,
and either renders the planned `sudo sysadminctl …` invocation
(`--dry-run`) or executes it (real mode). The next verb is `destroy`.

This crate is a Rust port of an earlier Go prototype (lives at
`/Users/plugin-dev/src/tenant/` for cross-reference). The Rust version
does not mirror the Go shape literally; it follows Rust idioms (clap derive,
composition-root DI, trait-object Reader, etc.) and has diverged where the
two languages' conventions diverge.

## Roadmap snapshot

Done:
- Project init, justfile + pre-commit gates (`fmt --check` + `clippy -D warnings`)
- `tenant create <name>` works in both dry-run and real mode (V1.5–V1.7)
- `accounts::Reader` trait + `StubReader` (test) + `MacosReader` (dscl)
- `accounts::Writer` trait + `MacosWriter` (sysadminctl-backed via Executor)
- `accounts::validate_name` (lexical: `[a-z][a-z0-9_-]{0,30}`, `EX_USAGE` on fail)
- `accounts::check_conflict` (state-based via Reader, `EX_USAGE` on fail)
- `allocation::UidAllocator::lowest_free_uid` (iterate from `TENANT_UID_FLOOR = 600`)
- `executor::Executor` trait + `SystemExecutor` (real, captures stderr) +
  `DryRunExecutor` (Ok-noop, swapped in at composition root when `--dry-run`) +
  `StubExecutor` (records calls; `failing` / `failing_with` for failure-path tests)
- `Reporter` + `Message`: Reporter holds `(stdout, stderr, verbose, dry_run)`;
  Message holds `(summary, summary_verbose, dry_run_summary, detail)`; methods
  are `emit_err` (always-on-stderr), `emit_real_only` (silent in dry), and
  `emit_dry_only` (silent in real). Verbose / dry-run mode selection is
  centralized in Reporter.
- Post-exec UX (V1.7): standard real mode emits one confirmation line
  ("Created tenant 'X'."); verbose adds pre-exec intent + mechanism preview
  and inlines UID into the confirmation. Sysadminctl noise suppressed on
  success, surfaced via `ExecError::NonZero { code, stderr }` on failure.
- E2E test suite in `tests/cli.rs` (reverse pyramid — no inline unit tests),
  24 cases via `run_with` / `run_with_exec` helpers
- macOS-gated smoke test exercises real dscl

Open / likely next:
- **`destroy <name>`** — natural pair to `create`. Reuses the same seams
  (Reader for pre-flight state checks, Writer for the action, Executor for
  exec, Reporter for output). Open design questions: pre-flight guards
  (require user exists? refuse non-tenant accounts via UID floor / name
  charset?), home-directory handling (sysadminctl `-deleteUser` defaults vs
  `-secure` shred vs `-keep`), primary-group residue (sysadminctl removes
  the user account but may leave the group), idempotence on missing user,
  confirmation flag (`--yes` per the seven-verb spec convention).
- **`status <name>`** — read-only verb; exercises the Reader without
  needing the Writer or Executor. Will likely surface `--strict` (exit
  code on drift) and `--json` (format) as orthogonal axes.
- **`doctor`** — host-level diagnostic. Multi-line default output will
  likely force `Vec<String>` generalization on `Message` fields.

## File map

```
src/lib.rs        — public API: pub fn run; declares modules; Cli + Verb + parse;
                    composition-root mode swap (DryRunExecutor when cli.dry_run)
src/commands.rs   — dispatch (the match on Verb) — no I/O, no cli.dry_run check;
                    emits errors via reporter.emit_err
src/accounts.rs   — Reader + Writer traits; StubReader / MacosReader (dscl);
                    MacosWriter (argv build + Reporter emit + Executor delegation);
                    validate_name, check_conflict
src/allocation.rs — UidAllocator + TENANT_UID_FLOOR
src/executor.rs   — Executor trait; SystemExecutor / DryRunExecutor / StubExecutor;
                    ExecError { Spawn, NonZero { code, stderr } }
src/messages.rs   — Message struct (summary / summary_verbose / dry_run_summary /
                    detail) + per-action factories (e.g. would_create_tenant /
                    creating_tenant / created_tenant for the create verb)
src/reporter.rs   — Reporter holds (stdout, stderr, verbose, dry_run); methods
                    emit_err / emit_real_only / emit_dry_only with mode-aware
                    summary selection
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
  `reporter.emit_err(...)` (failure paths), return `u8`. They never touch
  raw writers, check `cli.verbose`, or check `cli.dry_run`. Writers
  (`accounts::Writer`) also emit via Reporter — they're explicitly an
  I/O layer (they shell out) and own intent + mechanism rendering for
  their own actions, using `emit_real_only` / `emit_dry_only` to scope
  output to the appropriate mode.
- **Lexical → state-based check order** — `validate_name` runs before
  `check_conflict` in dispatch. Cheaper failure first.
- **Composition-root DI** — `tenant::run` takes `&dyn accounts::Reader`
  and `&dyn executor::Executor`. `main.rs` builds the prod impls
  (`MacosReader`, `SystemExecutor`); tests build their own (`StubReader`,
  `StubExecutor` / `NeverExecutor`). Writer is constructed inside `run`
  from the active Executor (DryRunExecutor swapped in when `cli.dry_run`),
  so the test seam stays at the Executor boundary while the Writer is an
  internal implementation detail.
- **Exit codes** — `0` success; `64` (`EX_USAGE`, sysexits.h) for any
  user-input failure (validation, conflict); `74` (`EX_IOERR`) reserved for
  dscl / process-execution failure; `1` is clap's default for parse errors
  (we don't override).
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
| `destroy <name>` | teardown | open |

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
