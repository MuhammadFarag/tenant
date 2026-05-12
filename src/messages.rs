use crate::accounts::{ConflictError, NameError, tenant_share_group_name};
use crate::executor::AccountError;
use crate::profile::{ProfileError, display_path_for};

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

/// One step in a plan — a pre-rendered display line plus an optional
/// `# <note>` annotation suffix. The annotation channel lets conditional
/// steps signal their conditionality in the upfront plan (cycle 1's `# on
/// rollback`; cycle 2's `# on reload failure` will share the same shape).
/// Borrows the rendered string from a let-bound `String` in the writer
/// scope so the plan can be built once and indexed for both the upfront
/// `detail` block and per-step `$` echo lines without cloning.
pub(crate) struct PlanStep<'a> {
    pub rendered: &'a str,
    pub annotation: Option<&'static str>,
}

impl<'a> PlanStep<'a> {
    pub fn plain(rendered: &'a str) -> Self {
        Self {
            rendered,
            annotation: None,
        }
    }

    pub fn annotated(rendered: &'a str, note: &'static str) -> Self {
        Self {
            rendered,
            annotation: Some(note),
        }
    }
}

/// Pre-exec dry-run message: "Would create tenant 'X'." plus the planned
/// multi-step plan as detail. Phase 3 issues two real exec calls
/// (group-first then sysadminctl) plus a third `# on rollback` annotated
/// line that documents what fires if sysadminctl fails after the group
/// was created; cycle 1 adds the profile-write step as a fourth
/// pretend-shell `tee <path> < default.toml` line. The rollback line is
/// always in the plan — pre-exec can't know what runtime will do, so the
/// operator sees the full algorithm. The annotation is cycle 2.0's
/// generalization that lets cycle 2 layer in PF-restore steps the same way.
/// Emitted via `emit_dry_only`.
pub(crate) fn would_create_tenant(name: &str, plan: &[PlanStep<'_>]) -> Message {
    Message {
        summary: Some(format!("Would create tenant '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(render_plan(plan)),
    }
}

/// Pre-exec real-mode counterpart of `would_create_tenant`. Same plan;
/// summary lives in `summary_verbose` so standard real mode stays silent
/// until the post-exec confirmation. Pairs with `running` emissions that
/// follow during execution. The success-path `$` echo omits the rollback
/// line; the failure path adds it back. Emitted via `emit_real_only`.
pub(crate) fn creating_tenant(name: &str, plan: &[PlanStep<'_>]) -> Message {
    Message {
        summary: None,
        summary_verbose: Some(format!("Creating tenant '{name}'.")),
        dry_run_summary: None,
        detail: Some(render_plan(plan)),
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
/// returns non-zero. The captured stderr (carried inside
/// `AccountError::NonZero`) flows through `AccountError::Display` and
/// gets appended after the "process exited with code N" prefix when
/// present. Emitted via `emit_err`.
pub(crate) fn create_failed(name: &str, error: &AccountError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to create '{name}': {error}")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Error-path message for the create verb when the profile-write step
/// fails after dseditgroup + sysadminctl have both succeeded. Names the
/// display-form profile path (with literal `~`) so the operator can
/// inspect / repair it directly without having to grep source. The
/// failure leaves the user + group on the host (per locked policy);
/// recovery is `tenant destroy <name>`. Emitted via `emit_err`.
pub(crate) fn create_profile_failed(name: &str, error: &ProfileError) -> Message {
    Message {
        summary: Some(format!(
            "tenant: failed to write profile '{}' for '{name}': {error}",
            display_path_for(name)
        )),
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
pub(crate) fn create_group_failed(name: &str, error: &AccountError) -> Message {
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
pub(crate) fn rollback_failed(name: &str, error: &AccountError) -> Message {
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
/// 'X'." with the full pessimistic plan as detail. Multi-step because
/// destroy issues sysadminctl `-deleteUser` plus a dscl `-read` residue
/// probe plus a conditional `dscl -delete` cleanup plus the
/// dseditgroup-delete plus the profile-rm. The dscl-delete is shown
/// unconditionally — dry-run can't know what the probe would have found,
/// so the operator sees the algorithm. Emitted via `emit_dry_only`.
pub(crate) fn would_destroy_tenant(name: &str, plan: &[PlanStep<'_>]) -> Message {
    Message {
        summary: Some(format!("Would destroy tenant '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(render_plan(plan)),
    }
}

/// Pre-exec real-mode twin of `creating_tenant`. Same multi-step plan
/// rendering as `would_destroy_tenant`, but verbose-only (the summary
/// lives in `summary_verbose`) so standard real mode stays silent until
/// the post-exec confirmation. Pairs with `running` emissions that follow
/// during execution. Emitted via `emit_real_only`.
pub(crate) fn destroying_tenant(name: &str, plan: &[PlanStep<'_>]) -> Message {
    Message {
        summary: None,
        summary_verbose: Some(format!("Destroying tenant '{name}'.")),
        dry_run_summary: None,
        detail: Some(render_plan(plan)),
    }
}

/// Per-step echo line: `$ <rendered>`. Cycle 2.0 unification — both real
/// shell-outs and synthetic steps (profile-write, profile-remove) flow
/// through this one factory; the rendered string is whatever the
/// substrate's `describe_*` method produced for the step. Verbose-only
/// (lives in `summary_verbose`); emitted via `emit_real_only` so dry-run
/// stays silent.
pub(crate) fn running(rendered: &str) -> Message {
    Message {
        summary: None,
        summary_verbose: Some(format!("$ {rendered}")),
        dry_run_summary: None,
        detail: None,
    }
}

/// Post-exec real-mode confirmation. Unlike `created_tenant`, no UID is
/// inlined in verbose: a destroyed account's old UID is not new
/// information to the operator who just asked us to destroy it. Emitted
/// via `emit_real_only`.
pub(crate) fn destroyed_tenant(name: &str) -> Message {
    Message {
        summary: Some(format!("Destroyed tenant '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Error-path twin of `create_failed`. Emitted via `emit_err` when any
/// account-domain step (sysadminctl-delete, dscl-cleanup, or
/// dseditgroup-delete) returns non-zero; captured stderr flows through
/// `AccountError::Display`.
pub(crate) fn destroy_failed(name: &str, error: &AccountError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to destroy '{name}': {error}")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Error-path message for destroy when the profile-rm step fails.
/// Surfaces the display-form profile path so the operator can inspect
/// it directly. The user + group are already gone (the failure is on
/// the 5th step), so the residual state is just the profile file —
/// usually a permission issue the operator can clear with a manual
/// `rm`. Emitted via `emit_err`.
pub(crate) fn destroy_profile_failed(name: &str, error: &ProfileError) -> Message {
    Message {
        summary: Some(format!(
            "tenant: failed to remove profile '{}' for '{name}': {error}",
            display_path_for(name)
        )),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Pre-exec dry-run message for the orphan-group convergence path.
/// Standard mode names the tenant (parallel to the rest of the destroy
/// UX — the operator typed `tenant destroy dev`); verbose adds the
/// suffixed group name and the mechanism so the operator can see and
/// grep for the literal resource. Emitted via `emit_dry_only`.
pub(crate) fn would_destroy_orphan_group(name: &str, plan: &[PlanStep<'_>]) -> Message {
    let group = tenant_share_group_name(name);
    Message {
        summary: Some(format!("Would destroy orphan group for tenant '{name}'.")),
        summary_verbose: Some(format!(
            "Would destroy orphan group '{group}' for tenant '{name}'."
        )),
        dry_run_summary: None,
        detail: Some(render_plan(plan)),
    }
}

/// Pre-exec real-mode counterpart: "Destroying orphan group …". Summary
/// lives in `summary_verbose` (silent in standard real mode); verbose
/// adds the suffixed group name. Pairs with the `running` emissions
/// that follow. Emitted via `emit_real_only`.
pub(crate) fn destroying_orphan_group(name: &str, plan: &[PlanStep<'_>]) -> Message {
    let group = tenant_share_group_name(name);
    Message {
        summary: None,
        summary_verbose: Some(format!(
            "Destroying orphan group '{group}' for tenant '{name}'."
        )),
        dry_run_summary: None,
        detail: Some(render_plan(plan)),
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
/// Verbose adds the single-step mechanism preview. Single-step plan
/// (unlike create/destroy) — there's no fan-out, just `sudo -iu <name>`.
/// Emitted via `emit_dry_only`.
pub(crate) fn would_shell_into_tenant(name: &str, rendered: &str) -> Message {
    Message {
        summary: Some(format!("Would shell into '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(format!("  {rendered}")),
    }
}

/// Pre-exec real-mode twin: "Shelling into 'X'." Unlike create/destroy
/// where the summary lives in `summary_verbose` (silent standard mode,
/// post-exec confirmation does the talking), shell has no post-exec
/// confirmation — the operator IS the shell after this fires. So the
/// "Shelling into" line is the only acknowledgement the operator gets,
/// and it shows in both standard and verbose. Emitted via
/// `emit_real_only`.
pub(crate) fn shelling_into_tenant(name: &str, rendered: &str) -> Message {
    Message {
        summary: Some(format!("Shelling into '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(format!("  {rendered}")),
    }
}

/// Error-path message for the shell verb when `login` returns
/// `AccountError` (spawn failure — sudo not found, fork failed).
/// Distinct from `create_failed` / `destroy_failed` so log-greps can
/// disambiguate the verb. Non-zero shell exits are NOT errors here;
/// they're propagated as tenant's own exit code by the dispatcher.
pub(crate) fn shell_failed(name: &str, error: &AccountError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to shell into '{name}': {error}")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Refusal message for `shell <name>` where the tenant doesn't exist
/// (NotPresent or OrphanGroup eligibility — per Q3, OrphanGroup
/// collapses to the same refusal because the group alone can't host a
/// shell session). Maps to EX_USAGE at the dispatch layer. Frames the
/// action as "cannot shell into" rather than "refusing to" because the
/// issue is "the target doesn't exist," not a guard-rail refusing an
/// unsafe operation.
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
/// destroy — same floor, different verb framing ("refusing to shell
/// into" vs "refusing to destroy"). Names the floor explicitly so the
/// operator can disambiguate without reading the source.
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
/// user listing but has no positive UID — twin of
/// `system_account_refusal` for destroy. Same `(true, None)` Reader
/// pattern; same refusal rationale (the account very much exists; we
/// just won't shell into it).
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
/// so destroy is a successful no-op. Tense-neutral so the same line
/// works in real and dry-run modes (no separate "Would …" twin).
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
/// both. The group-side messages name the suffixed group literally so
/// the operator can run `dscl . -read /Groups/<name>-tenant-share`
/// directly without having to guess the convention. Emitted via
/// `emit_err`; produces `EX_USAGE 64` at the dispatch layer.
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

/// Render a multi-step plan as a single newline-separated string with
/// `  ` (two-space) indentation per line, plus an optional `  # …`
/// annotation suffix per step. The Reporter writes the composite as one
/// `detail` block; the indentation distinguishes plan lines from the
/// `$ ` execution-echo lines emitted by `running`.
fn render_plan(steps: &[PlanStep<'_>]) -> String {
    steps
        .iter()
        .map(|step| match step.annotation {
            Some(note) => format!("  {}  # {note}", step.rendered),
            None => format!("  {}", step.rendered),
        })
        .collect::<Vec<_>>()
        .join("\n")
}
