# tenant — Rust port of the macOS tenant-account CLI

A small CLI for provisioning macOS user accounts (and matching primary
groups) in a project-reserved UID range (≥600). Currently in dry-run-only
territory: the binary inspects host account state, validates input, picks
the next free UID, and prints what `sudo sysadminctl …` *would* run.
Real-mode execution is a deliberate next step.

This crate is a Rust port of an earlier Go prototype (lives at
`/Users/plugin-dev/src/tenant/` for cross-reference). The Rust version
does not mirror the Go shape literally; it follows Rust idioms (clap derive,
composition-root DI, trait-object Reader, etc.) and has diverged where the
two languages' conventions diverge.

## Roadmap snapshot

Done:
- Project init, justfile + pre-commit gates (`fmt --check` + `clippy -D warnings`)
- `tenant create <name> --dry-run` with intent / mechanism output and `-v`
- `accounts::Reader` trait + `StubReader` (test) + `MacosReader` (dscl)
- `accounts::validate_name` (lexical: `[a-z][a-z0-9_-]{0,30}`, `EX_USAGE` on fail)
- `accounts::check_conflict` (state-based via Reader, `EX_USAGE` on fail)
- `allocation::UidAllocator::lowest_free_uid` (iterate from `TENANT_UID_FLOOR = 600`)
- `Reporter` + `Message` (summary / detail, both `Option<String>`; verbose
  decision lives only in `Reporter::write` / `write_err`)
- E2E test suite in `tests/cli.rs` (reverse pyramid — no inline unit tests)
- macOS-gated smoke test exercises real dscl

Open / likely next:
- **Real-mode `create`** — currently `tenant create dev` (without `--dry-run`)
  silently returns 0. Decide whether to (a) actually exec `sudo sysadminctl`
  via a process-execution seam, or (b) make `--dry-run` clap-required, or
  (c) emit "real-mode unimplemented" to stderr and return non-zero. Option
  (a) introduces the executor abstraction we'll need for every future
  side-effecting verb.
- **Second verb** — pick from the seven-verb spec below. `destroy` is the
  natural pair to `create`; `status` exercises read-only paths; `doctor`
  has multi-line default output and will likely force `Vec<String>`
  generalization on `Message.summary` / `detail`.
- **Write-side `accounts` API** — when real-mode lands, we'll add the
  side-effecting half (dscl is read-only; `sysadminctl` is the writer).

## File map

```
src/lib.rs        — public API: pub fn run; declares modules; Cli + Command + parse
src/commands.rs   — dispatch (the match) — no I/O, no cli.verbose; emits via Reporter
src/accounts.rs   — Reader trait, StubReader, MacosReader; validate_name, check_conflict
src/allocation.rs — UidAllocator + TENANT_UID_FLOOR
src/messages.rs   — Message struct + factory functions (would_create_tenant, invalid_name, name_conflict)
src/reporter.rs   — Reporter holds (stdout, stderr, verbose); renders Message via write/write_err
src/main.rs       — composition root: MacosReader::new(), then tenant::run

tests/cli.rs      — every test goes here; helper fn run_with(stub, args) -> (u8, String, String)
```

## Project doctrine

Things that are easy to violate and would matter:

- **Intent / mechanism split** — every user-facing emission has a "summary"
  (always shown) and an optional "detail" (verbose only). Action messages
  also carry a `dry_run_summary` (Reporter picks it in dry-run mode; falls
  back to `summary` when None, which is how error / conflict messages stay
  mode-agnostic). Factories live in `messages.rs`, named after the domain
  action (e.g. `create_tenant_action`).
- **No I/O in command logic** — verbs receive `&mut Reporter`, emit via
  `reporter.emit(...)` / `emit_err(...)`, return `u8`. They never touch
  raw writers or check `cli.verbose`. Writers (`accounts::Writer`) also
  emit via Reporter — they're explicitly an I/O layer (they shell out)
  and own intent + mechanism rendering for their own actions.
- **Lexical → state-based check order** — `validate_name` runs before
  `check_conflict` in dispatch. Cheaper failure first.
- **Composition-root DI** — `tenant::run` takes `&dyn accounts::Reader` plus
  writers. `main.rs` builds the prod impl (`MacosReader`); tests build their
  own (`StubReader`). No Deps struct, no `run` / `run_with` split.
- **Exit codes** — `0` success; `64` (`EX_USAGE`, sysexits.h) for any
  user-input failure (validation, conflict); `74` (`EX_IOERR`) reserved for
  dscl / process-execution failure; `1` is clap's default for parse errors
  (we don't override).
- **Acronym casing** — Rust convention treats acronyms as words: `Uid`
  not `UID`, `Macos` not `MacOS`. Methods are `lowest_free_uid`, struct
  is `UidAllocator`, `MacosReader`.
- **Clap flag scoping** — `-v / --verbose` is `global = true`;
  subcommand-scoped flags like `--dry-run` stay on their subcommand.

## Test discipline

E2E-only. All tests live in `tests/cli.rs` and drive through `tenant::run`
with a `StubReader`. Inline `#[cfg(test)] mod tests` blocks are out of style
on this project; unit tests need explicit justification (combinatorial
coverage that's awkward via the CLI surface, etc.) — the bar is high.

The `run_with(stub, &["create", "dev", "--dry-run"]) -> (u8, String, String)`
helper runs the binary in-process and returns exit code + stdout + stderr
as `String`s. Use it for new tests; don't duplicate the writer/args setup.

Byte-exact assertions on rendered output are the norm. They pin the
user-facing contract; cosmetic message tweaks need test edits.

## Local dev

```
just check        # fmt + clippy -D warnings + test (pre-merge gate)
just fmt          # in-place format
just test         # cargo test
cargo run --quiet -- create somename --dry-run -v
```

Pre-commit hooks run `cargo fmt --check` (via `just check-fmt`) and
`cargo clippy --all-targets -- -D warnings` on commits touching `.rs`.
They're local-only (`language: system`), no PyPI / GitHub deps. Run
`pre-commit install` once after a fresh clone if the hook isn't wired.

## The seven-verb spec (forward-looking design)

From the project's design consensus:

| verb | role | status |
|---|---|---|
| `create <name>` | one-shot provisioning | ✓ dry-run only |
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
