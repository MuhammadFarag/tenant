use crate::accounts::{ConflictError, NameError, tenant_share_group_name};
use crate::executor::ExecError;

pub(crate) struct Message {
    /// Default rendering, used in real+standard mode and as ultimate
    /// fallback when no mode-specific override is populated.
    pub summary: Option<String>,
    /// Override used in real+verbose mode (e.g. to inline UID into the
    /// confirmation line). Falls back to `summary` when None.
    pub summary_verbose: Option<String>,
    /// Override used in dry-run mode. Falls back to `summary` when None.
    pub dry_run_summary: Option<String>,
    /// Verbose-only second line, shown in either mode.
    pub detail: Option<String>,
}

/// Pre-exec dry-run message: "Would create tenant 'X'." plus the planned
/// 3-line plan as detail. Phase 3 issues two exec calls (group-first then
/// sysadminctl) plus a third "on rollback" line that documents what fires
/// if sysadminctl fails after the group was created. The rollback line is
/// always in the plan — pre-exec can't know what runtime will do, so the
/// operator sees the full algorithm. Emitted via `emit_dry_only`.
pub(crate) fn would_create_tenant(
    name: &str,
    group_argv: &[String],
    user_argv: &[String],
    rollback_argv: &[String],
) -> Message {
    Message {
        summary: Some(format!("Would create tenant '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(render_create_plan(group_argv, user_argv, rollback_argv)),
    }
}

/// Pre-exec real-mode counterpart of `would_create_tenant`. Same 3-line
/// plan; summary lives in `summary_verbose` so standard real mode stays
/// silent until the post-exec confirmation. Pairs with `running_argv`
/// emissions that follow during execution. The success-path `$` echo has
/// only 2 lines (no rollback); cycle 3's rollback path adds the 3rd
/// echo. Emitted via `emit_real_only`.
pub(crate) fn creating_tenant(
    name: &str,
    group_argv: &[String],
    user_argv: &[String],
    rollback_argv: &[String],
) -> Message {
    Message {
        summary: None,
        summary_verbose: Some(format!("Creating tenant '{name}'.")),
        dry_run_summary: None,
        detail: Some(render_create_plan(group_argv, user_argv, rollback_argv)),
    }
}

/// Post-exec real-mode confirmation. UID and GID are both shown only in
/// verbose (inlined into the summary). Phase 3 inlines both because the
/// two allocators are now independent — neither value is implied by the
/// other. Emitted via `emit_real_only` so it doesn't lie about successful
/// creation in dry-run mode.
pub(crate) fn created_tenant(name: &str, uid: u32, gid: u32) -> Message {
    Message {
        summary: Some(format!("Created tenant '{name}'.")),
        summary_verbose: Some(format!("Created tenant '{name}' (UID {uid}, GID {gid}).")),
        dry_run_summary: None,
        detail: None,
    }
}

/// Error-path message for the create verb when sysadminctl-addUser
/// returns non-zero. Cycle 3 wires this. The captured stderr (carried
/// inside `ExecError::NonZero`) flows through `ExecError::Display` and
/// gets appended after the "process exited with code N" prefix when
/// present. Emitted via `emit_err`.
pub(crate) fn create_failed(name: &str, error: &ExecError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to create '{name}': {error}")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Error-path message for the create verb when dseditgroup-create
/// returns non-zero. Distinct from `create_failed` because the failure
/// state is different — the user wasn't touched, so the operator's
/// remediation is different (no orphan user to clean up, just retry the
/// create). Names the suffixed group literally so the operator can
/// inspect it directly via dscl.
pub(crate) fn create_group_failed(name: &str, error: &ExecError) -> Message {
    let group = tenant_share_group_name(name);
    Message {
        summary: Some(format!(
            "tenant: failed to create group '{group}' for '{name}': {error}"
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Second-emission companion to `create_failed` for the case where the
/// rollback dseditgroup-delete itself failed. Names the orphan group and
/// the recovery path — the em-dash trailing clause is load-bearing UX:
/// the operator shouldn't have to read the source to know that next
/// `tenant destroy <name>` will converge via the OrphanGroup eligibility
/// arm. Emitted via a second `emit_err` call right after `create_failed`,
/// so the operator gets both lines in a predictable order.
pub(crate) fn rollback_failed(name: &str, error: &ExecError) -> Message {
    let group = tenant_share_group_name(name);
    Message {
        summary: Some(format!(
            "tenant: rollback of group '{group}' also failed: {error} \
             \u{2014} host now has an orphan group; next 'tenant destroy {name}' will converge"
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Pre-exec dry-run twin of `would_create_tenant`. "Would destroy tenant
/// 'X'." with the full pessimistic plan as detail (one indented argv per
/// line). Multi-argv because destroy issues sysadminctl `-deleteUser` plus
/// a dscl `-read` residue probe plus a conditional `dscl -delete` cleanup.
/// The dscl-delete is shown unconditionally — dry-run can't know what the
/// probe would have found, so the operator sees the algorithm. Emitted via
/// `emit_dry_only`.
pub(crate) fn would_destroy_tenant(name: &str, argvs: &[&[String]]) -> Message {
    Message {
        summary: Some(format!("Would destroy tenant '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(render_plan(argvs)),
    }
}

/// Pre-exec real-mode twin of `creating_tenant`. Same multi-argv plan
/// rendering as `would_destroy_tenant`, but verbose-only (the summary
/// lives in `summary_verbose`) so standard real mode stays silent until the
/// post-exec confirmation. Pairs with `running_argv` emissions that follow
/// during execution. Emitted via `emit_real_only`.
pub(crate) fn destroying_tenant(name: &str, argvs: &[&[String]]) -> Message {
    Message {
        summary: None,
        summary_verbose: Some(format!("Destroying tenant '{name}'.")),
        dry_run_summary: None,
        detail: Some(render_plan(argvs)),
    }
}

/// Per-exec echo line emitted just before each Executor.run call during a
/// real-verbose run: `$ <argv>`. Follows the upfront plan block so the
/// operator sees the planned commands first, then which ones actually ran
/// (the dscl-delete cleanup is conditional, so its `$` line is absent when
/// the probe finds DS clean). Verbose-only (lives in `summary_verbose`);
/// emitted via `emit_real_only` so dry-run stays silent.
pub(crate) fn running_argv(argv: &[String]) -> Message {
    Message {
        summary: None,
        summary_verbose: Some(format!("$ {}", shell_join(argv))),
        dry_run_summary: None,
        detail: None,
    }
}

/// Post-exec real-mode confirmation. Unlike `created_tenant`, no UID is
/// inlined in verbose: a destroyed account's old UID is not new information
/// to the operator who just asked us to destroy it. Emitted via
/// `emit_real_only`.
pub(crate) fn destroyed_tenant(name: &str) -> Message {
    Message {
        summary: Some(format!("Destroyed tenant '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Error-path twin of `create_failed`. Emitted via `emit_err` when
/// sysadminctl `-deleteUser` returns non-zero; captured stderr flows
/// through `ExecError::Display`.
pub(crate) fn destroy_failed(name: &str, error: &ExecError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to destroy '{name}': {error}")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Pre-exec dry-run message for the orphan-group convergence path.
/// Standard mode names the tenant (parallel to the rest of the destroy UX
/// — the operator typed `tenant destroy dev`); verbose adds the suffixed
/// group name and the mechanism so the operator can see and grep for
/// the literal resource. Emitted via `emit_dry_only`.
pub(crate) fn would_destroy_orphan_group(name: &str, argv: &[String]) -> Message {
    let group = tenant_share_group_name(name);
    Message {
        summary: Some(format!("Would destroy orphan group for tenant '{name}'.")),
        summary_verbose: Some(format!(
            "Would destroy orphan group '{group}' for tenant '{name}'."
        )),
        dry_run_summary: None,
        detail: Some(format!("  {}", shell_join(argv))),
    }
}

/// Pre-exec real-mode counterpart: "Destroying orphan group …". Summary
/// lives in `summary_verbose` (silent in standard real mode); verbose
/// adds the suffixed group name. Pairs with the `running_argv` emission
/// that follows. Emitted via `emit_real_only`.
pub(crate) fn destroying_orphan_group(name: &str, argv: &[String]) -> Message {
    let group = tenant_share_group_name(name);
    Message {
        summary: None,
        summary_verbose: Some(format!(
            "Destroying orphan group '{group}' for tenant '{name}'."
        )),
        dry_run_summary: None,
        detail: Some(format!("  {}", shell_join(argv))),
    }
}

/// Post-exec real-mode confirmation: "Destroyed orphan group …". Mirror
/// of `created_tenant`'s standard/verbose split — standard names the
/// tenant; verbose names the literal group as well. Emitted via
/// `emit_real_only`.
pub(crate) fn destroyed_orphan_group(name: &str) -> Message {
    let group = tenant_share_group_name(name);
    Message {
        summary: Some(format!("Destroyed orphan group for tenant '{name}'.")),
        summary_verbose: Some(format!(
            "Destroyed orphan group '{group}' for tenant '{name}'."
        )),
        dry_run_summary: None,
        detail: None,
    }
}

/// Pre-exec dry-run message for the shell verb: "Would shell into 'X'."
/// Verbose adds the single-argv mechanism preview. Single-argv plan
/// (unlike create/destroy) — there's no fan-out, just `sudo -iu <name>`.
/// Emitted via `emit_dry_only`.
pub(crate) fn would_shell_into_tenant(name: &str, argv: &[String]) -> Message {
    Message {
        summary: Some(format!("Would shell into '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(format!("  {}", shell_join(argv))),
    }
}

/// Pre-exec real-mode twin: "Shelling into 'X'." Unlike create/destroy
/// where the summary lives in `summary_verbose` (silent standard mode,
/// post-exec confirmation does the talking), shell has no post-exec
/// confirmation — the operator IS the shell after this fires. So the
/// "Shelling into" line is the only acknowledgement the operator gets,
/// and it shows in both standard and verbose. Emitted via `emit_real_only`.
pub(crate) fn shelling_into_tenant(name: &str, argv: &[String]) -> Message {
    Message {
        summary: Some(format!("Shelling into '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(format!("  {}", shell_join(argv))),
    }
}

/// Error-path message for the shell verb when `exec_into` returns
/// `ExecError` (spawn failure — sudo not found, fork failed). Distinct
/// from `create_failed` / `destroy_failed` so log-greps can disambiguate
/// the verb. Non-zero shell exits are NOT errors here; they're propagated
/// as tenant's own exit code by the dispatcher.
pub(crate) fn shell_failed(name: &str, error: &ExecError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to shell into '{name}': {error}")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Refusal message for `shell <name>` where the tenant doesn't exist
/// (NotPresent or OrphanGroup eligibility — per Q3, OrphanGroup collapses
/// to the same refusal because the group alone can't host a shell session).
/// Maps to EX_USAGE at the dispatch layer. Frames the action as "cannot
/// shell into" rather than "refusing to" because the issue is "the target
/// doesn't exist," not a guard-rail refusing an unsafe operation.
pub(crate) fn shell_absent(name: &str) -> Message {
    Message {
        summary: Some(format!(
            "tenant: cannot shell into '{name}': does not exist"
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Refusal message for `shell <name>` where the account exists with a
/// positive UID below the tenant floor. Twin of `not_a_tenant` for
/// destroy — same floor, different verb framing ("refusing to shell into"
/// vs "refusing to destroy"). Names the floor explicitly so the operator
/// can disambiguate without reading the source.
pub(crate) fn shell_not_a_tenant(name: &str, uid: u32, floor: u32) -> Message {
    Message {
        summary: Some(format!(
            "tenant: refusing to shell into '{name}': UID {uid} is below tenant floor {floor}"
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Refusal message for `shell <name>` where the account exists in the
/// user listing but has no positive UID — twin of `system_account_refusal`
/// for destroy. Same `(true, None)` Reader pattern; same refusal rationale
/// (the account very much exists; we just won't shell into it).
pub(crate) fn shell_system_account_refusal(name: &str) -> Message {
    Message {
        summary: Some(format!(
            "tenant: refusing to shell into '{name}': system account (no tenant-range UID)"
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Convergent-noop message for the destroy verb: account already absent,
/// so destroy is a successful no-op. Tense-neutral so the same line works
/// in real and dry-run modes (no separate "Would …" twin).
pub(crate) fn destroy_absent(name: &str) -> Message {
    Message {
        summary: Some(format!("tenant '{name}' does not exist; nothing to do.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Refusal message for `destroy <name>` where the account exists with a
/// positive UID below the tenant floor — i.e. it's a system or human
/// account that happens to have a tenant-shaped name. Names the floor
/// explicitly so the operator can tell why we refused without having to
/// read the source.
pub(crate) fn not_a_tenant(name: &str, uid: u32, floor: u32) -> Message {
    Message {
        summary: Some(format!(
            "tenant: refusing to destroy '{name}': UID {uid} is below tenant floor {floor}"
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Refusal message for `destroy <name>` where the account exists in the
/// user listing but has no positive UID — i.e. it's a service account
/// (`nobody` is the canonical case, UID -2 on macOS) that's been
/// filtered out of the UID map. We refuse rather than noop because the
/// account very much exists; the operator should know that.
pub(crate) fn system_account_refusal(name: &str) -> Message {
    Message {
        summary: Some(format!(
            "tenant: refusing to destroy '{name}': system account (no tenant-range UID)"
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Validation-failure refusal message. Shared by both create and destroy
/// dispatch arms via `validate_name`'s `NameError` variants. Emitted via
/// `emit_err`; produces `EX_USAGE 64` at the dispatch layer.
pub(crate) fn invalid_name(name: &str, error: &NameError) -> Message {
    let summary = match error {
        NameError::Empty => "tenant: name cannot be empty".to_string(),
        NameError::InvalidStart(c) => {
            format!("tenant: name '{name}' must start with a lowercase letter (got '{c}')")
        }
        NameError::InvalidCharacter(c) => {
            format!("tenant: name '{name}' contains invalid character '{c}'")
        }
        NameError::TooLong { len, max } => {
            format!("tenant: name '{name}' is too long ({len} characters; maximum is {max})")
        }
        NameError::Reserved => {
            format!("tenant: name '{name}' is reserved (matches a system or role name)")
        }
    };
    Message {
        summary: Some(summary),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Conflict-refusal message for the create verb: the requested name is
/// already a user, the `<name>-tenant-share` group is already taken, or
/// both. The group-side messages name the suffixed group literally so the
/// operator can run `dscl . -read /Groups/<name>-tenant-share` directly
/// without having to guess the convention. Emitted via `emit_err`;
/// produces `EX_USAGE 64` at the dispatch layer.
pub(crate) fn name_conflict(name: &str, error: &ConflictError) -> Message {
    let group = tenant_share_group_name(name);
    let summary = match error {
        ConflictError::UserExists => format!("tenant: user '{name}' already exists"),
        ConflictError::GroupExists => format!("tenant: group '{group}' already exists"),
        ConflictError::Both => {
            format!("tenant: user '{name}' and group '{group}' already exist")
        }
    };
    Message {
        summary: Some(summary),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Shell-quote argv for display. Args containing whitespace get wrapped in
/// double quotes so the rendered line is paste-safe; bare args stay bare.
/// Used only for the verbose mechanism line — the executor takes argv
/// directly and never goes through a shell.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.chars().any(char::is_whitespace) {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render a multi-argv plan as a single newline-separated string with
/// `  ` (two-space) indentation per line. The Reporter writes the
/// composite as one `detail` block; the indentation distinguishes plan
/// lines from the `$ ` execution-echo lines emitted by `running_argv`.
fn render_plan(argvs: &[&[String]]) -> String {
    argvs
        .iter()
        .map(|a| format!("  {}", shell_join(a)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Specialized plan rendering for the create verb. Two normal plan lines
/// (group-create, user-create) plus a third line annotated `# on rollback`
/// that documents the conditional rollback step. The annotation isn't a
/// shell-comment in any literal sense — display-only — but matches the
/// `# on ...` shape sysadmin docs commonly use to flag conditional
/// commands, so it reads naturally next to the unannotated lines.
fn render_create_plan(group: &[String], user: &[String], rollback: &[String]) -> String {
    format!(
        "  {}\n  {}\n  {}  # on rollback",
        shell_join(group),
        shell_join(user),
        shell_join(rollback),
    )
}
