---
name: add-verb
description: Checklist for extending the tenant CLI surface — a new verb, flag, substrate Op variant, HostMachine method, or doctor Finding. Use when adding or reshaping any of those, to land every conventional piece (dispatch, Reporter triple, plan render, confirm, doctor subset, tests).
---

# Extending the tenant CLI

Work through the pieces that apply. CLAUDE.md doctrine (shape rules, exit
codes) governs throughout; this is the per-piece checklist.

## New substrate mutation

1. Decide the shape: fits `Result<(), E>` → new variant on the matching Op
   sub-ADT in `src/domain/ops.rs` (`AccountOp`/`ProfileOp`/`FirewallOp`/
   `AclOp`/`KeychainOp`/`PamOp`); non-unit return (exit code, content,
   probe verdict) → carve-out method on `HostMachine`. A new sub-domain is
   a `describe_*`/`execute_*` method pair + a leaf `Op<'_>` variant — never
   a new trait.
2. Implement describe (display string) + execute (argv) in
   `MacosHostMachine`; the executor is self-idempotent where the verb
   re-runs it. `DryRunHostMachine`: no-op execute, delegate describe, and
   pick read/probe placeholders that never manufacture a refusal in a
   preview.
3. Reuse existing error types where the substrate matches (`HostFileError`
   covers sudoers, pam.d, on-disk anchor); the error's Display names the
   path.
4. Pins: one test per new variant in `tests/macos_host_machine.rs`
   (describe argv contract) and `tests/intent_labels.rs`
   (`Op::intent_label()`).

## New verb (or verb arm)

1. `src/cli.rs`: variant with doc comments (they are the help text) + an
   `after_help` examples block. Global flags (`-v`/`--dry-run`/`-y`) come
   free; per-verb flags stay scoped.
2. `src/domain/tenants/<verb>.rs`: submodule owning its error type, the
   `impl Tenants` block, and helpers. Order checks lexical → state
   (`validate_name` before OS probes).
3. `src/domain/commands.rs`: dispatch arm + a `surface_<verb>_error` helper
   routing every error variant to a Reporter method. Build the plan/profile
   upfront so read failures surface pre-prompt.
4. `src/domain/reporter.rs`: `_intent`/`_summary`/`_done` triple + refusal/
   failure frames. All operator I/O and all verbose/dry-run branching lives
   here — command logic never touches writers or `cli.*` flags.
5. Prompt-bearing verbs: render the plan inside `*_summary` (verbose-gated),
   then `confirm` — Y-default, except destructive verbs (destroy) which are
   N-default; `setup`-style auth-stack items additionally decline on
   non-TTY without `--yes`. Skip summary+prompt unless
   `dry_run || stdin_is_tty`.
6. Mutating verbs run `pre_exec_doctor_summary` with an existing
   `DoctorScope` subset (reuse one unless the audited surface genuinely
   differs) between summary and confirm — courtesy, never an abort gate.
7. Exit codes: 0 success (convergent noops included), 64 user-input
   refusal, 74 substrate failure; shell-style child-exit propagation only
   where the verb wraps a child.
8. Fleet (no-arg) forms mirror `reload_all`: per-tenant failures recorded,
   walk continues, any failure ⇒ 74.

## New doctor Finding

1. Probes are `HostMachine` carve-outs (how doctor learns), never `Op`
   variants. Classification is a pure fn in `src/doctor.rs`; I/O stays in
   `Tenants::doctor_*`.
2. Author `guidance()` (Why / Fix / Side-effects / Alternative — omit
   Alternative when there's no distinct command) + a byte-form pin in
   `tests/doctor.rs`.
3. Gate genuine sudo probes on `sudo_session_cached` (caller-side split);
   auth-free reads run regardless.
4. Do not add a keychain locked-state probe — `security
   show-keychain-info` via `sudo -iu` triggers a SecurityAgent GUI prompt
   (see `shell.rs::unlock_tenant_keychain`).

## Tests

E2E-first in `tests/cli_<verb>.rs` (`mod adapters; mod common;`) through
`tenant::run`: behavioral assertions = op identity against
`StubHostMachine`; display assertions = byte-exact. `run_with` wires
`NeverHostMachine` (panics on any substrate call — the negative pin);
`run_with_exec` lets the test own the machine. Parser cross-cutting goes in
`tests/cli.rs`. Gate: `just check`.
