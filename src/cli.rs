use clap::{Parser, Subcommand, ValueEnum};

use crate::domain::TenantUserName;

#[derive(Parser)]
#[command(
    name = "tenant",
    version,
    disable_help_subcommand = true,
    about = "Provision isolated macOS tenant accounts with restricted network egress.",
    long_about = "Provision macOS user accounts, primary groups (named \
                  `<name>-tenant-share`) in a project-reserved UID/GID range \
                  (>= 600), a per-tenant profile (TOML at \
                  `~/.config/tenant/profiles/<name>.toml`), a per-tenant \
                  PF anchor (`/etc/pf.anchors/tenant-<name>`, referenced from \
                  `/etc/pf.conf`), and a per-tenant co-working directory at \
                  `/Users/Shared/tenants/<name>/` co-owned by host and tenant \
                  for collaborative work."
)]
pub struct Cli {
    /// Show the `Plan (commands to execute):` block in mutating-verb
    /// summaries; emit per-step progress lines during execution.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Preview without mutating the host: substitute a dry-run host
    /// substrate, render the full plan, and show the confirmation
    /// prompt as `(Real run would prompt: …)`.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Skip the interactive confirmation prompt that mutating verbs
    /// (create / destroy / mode / reload) emit before executing.
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,

    #[command(subcommand)]
    pub verb: Verb,
}

#[derive(Subcommand)]
pub enum Verb {
    /// Prepare this host to run tenants (opt-in, host-wide).
    ///
    /// Offers a menu of host-preparation items, today one: enabling
    /// Touch ID for sudo (appends `auth sufficient pam_tid.so` to
    /// `/etc/pam.d/sudo_local`, the OS-update-safe customization file).
    /// Each item is OPT-IN: the prompt defaults to no, and a non-TTY
    /// invocation without `--yes` declines rather than auto-applying an
    /// auth-stack change. `--yes` accepts every item (scripted host
    /// bootstrap); `--dry-run` previews without mutating.
    ///
    /// Distinct from the per-tenant verbs: no name argument, no
    /// eligibility checks, no pre-exec doctor pass — `setup` prepares the
    /// HOST, not a tenant. `tenant doctor` surfaces a Touch-ID-missing
    /// note that points here. Listed first because it's the natural
    /// first step: prepare the host, then `create` a tenant.
    Setup,
    /// Provision a new tenant: user account, share group, profile, PF anchor, co-working dir.
    ///
    /// Creates user `<name>` and group `<name>-tenant-share` in the
    /// tenant-reserved UID/GID range (>= 600), writes a scaffolded
    /// profile to `~/.config/tenant/profiles/<name>.toml`, installs a
    /// per-tenant PF anchor (egress blocked by default; allowlist hosts
    /// declared in the profile), and enables PF host-wide if not
    /// already enabled. The invoking host is added to the tenant's
    /// share group so RW shares the tenant creates stay host-writable.
    ///
    /// Also provisions a co-working directory at
    /// `/Users/Shared/tenants/<name>/` (mode 2770 + inheritable rw ACL
    /// for the share group) where host and tenant collaborate — files
    /// either side creates inside it are read/writable by the other.
    ///
    /// Recovery on partial failure: re-run `tenant destroy <name>`
    /// (idempotent / convergent) to clear any leftover host state.
    Create {
        /// Tenant short username. Must start with a lowercase letter,
        /// stay within macOS short-username constraints, and not collide
        /// with an existing user or with `<name>-tenant-share`. Allocated
        /// a UID at or above the tenant floor (600).
        name: TenantUserName,
    },
    /// Tear down a tenant. Convergent: absent => noop.
    ///
    /// Removes the user account (home moves to `/Users/Deleted Users/`
    /// and stays recoverable until that directory is emptied), removes the host
    /// from the share group, removes the share group, removes the PF
    /// anchor and flushes its in-kernel rules, and removes the profile.
    ///
    /// The co-working directory at `/Users/Shared/tenants/<name>/` is
    /// left intact (it may hold operator-authored work); a notice line
    /// names the path so the operator can clean up manually.
    ///
    /// Refuses with `EX_USAGE` if the named account exists but has a
    /// UID below the tenant floor (600) — that's not a tenant we
    /// provisioned. An orphan group (user gone, `<name>-tenant-share`
    /// survives a prior partial create) converges through the same
    /// verb: the group + PF state are cleaned up.
    Destroy {
        /// Tenant short username to destroy. Same charset constraints
        /// as `create`. Refused if the account exists but has a UID
        /// below the tenant floor (600).
        name: TenantUserName,
    },
    /// Reapply the tenant's profile to host state. Bare form walks every tenant.
    ///
    /// Always lands at runtime tier — install-tier widening stays the
    /// explicit `tenant mode <name> install` operator action. Re-renders
    /// and reloads the PF anchor from the current profile, re-applies
    /// declared `[[shares]]` (ACL grants recurse over each `host_path`
    /// tree so existing children pick up the share-group ACE) plus
    /// `$HOME`-rooted symlinks, re-applies the co-working directory
    /// (mode + recursive ACL — picks up subdirs the tenant added between
    /// reloads), and re-adds the host to the share group (catch-up for
    /// tenants provisioned before the host membership step existed).
    ///
    /// Bare `tenant reload` enumerates every tenant on the host and
    /// reloads each in turn; per-tenant failures don't abort the walk —
    /// the final summary names any failed tenants. Single-tenant
    /// failures exit `EX_IOERR` (74).
    Reload {
        /// Optional tenant short username. Omit to reload every tenant
        /// on the host in sequence.
        name: Option<TenantUserName>,
    },
    /// Apply a firewall widening level (install | runtime) to the tenant.
    ///
    /// Re-renders the PF anchor at the requested tier and reloads PF.
    /// `runtime` is the baseline; `install` widens to include the
    /// install-tier allowlist hosts (e.g. package registries, CDN
    /// mirrors needed for one-shot dependency installs).
    ///
    /// Install widening is intentionally non-persistent at the
    /// session boundary — `tenant shell <name>` auto-narrows to runtime
    /// tier on entry, so a forgotten `mode install` doesn't leak into a
    /// future shell session. To consume the wider allowlist for a single
    /// command without leaving install-tier on disk, prefer `tenant shell
    /// <name> --mode install -- <cmd>` (auto-narrows on completion).
    #[command(after_help = "\
Examples:
  tenant mode alice install              widen egress to the install-tier allowlist
  tenant mode alice runtime              narrow back to the runtime baseline")]
    Mode {
        /// Tenant short username.
        name: TenantUserName,
        /// `install` widens egress to include install-tier allowlist
        /// hosts; `runtime` narrows back to the baseline allowlist.
        #[arg(value_enum)]
        level: ModeLevel,
    },
    /// Apply an inbound loopback posture (restricted | permissive) to the tenant.
    ///
    /// Re-renders the PF anchor with the requested INBOUND loopback (TCP)
    /// posture and reloads PF. `restricted` (the default) allows inbound
    /// loopback only on the ports declared in the profile's `[inbound]`
    /// section — an empty list locks inbound entirely. `permissive` opens
    /// all inbound loopback TCP, for the localhost-redirect OAuth window
    /// (a service that binds a random port the operator can't predeclare).
    ///
    /// Permissive widening is intentionally non-persistent at the session
    /// boundary — `tenant shell <name>` auto-narrows inbound back to
    /// restricted on entry, so a forgotten `inbound permissive` doesn't
    /// leak into a future shell session.
    ///
    /// HONEST SCOPE: `restricted` is SURFACE-REDUCTION, not host-vs-peer
    /// isolation. A declared port is reachable by the host AND by peer
    /// tenants — pf cannot see the initiator on shared loopback
    /// (127.0.0.1). A tenant also cannot reach its OWN undeclared loopback
    /// port (declare it to restore intra-tenant use). UDP loopback is
    /// unfiltered (TCP only). The inbound and egress (`tenant mode`)
    /// widenings do NOT compose across separate commands: each verb renders
    /// the axis it does not control at steady state.
    #[command(after_help = "\
Examples:
  tenant inbound alice permissive        open all inbound loopback (OAuth-on-random-port window)
  tenant inbound alice restricted        narrow back to profile-declared ports")]
    Inbound {
        /// Tenant short username.
        name: TenantUserName,
        /// `permissive` opens all inbound loopback TCP; `restricted`
        /// narrows back to the profile's `[inbound]` declared ports
        /// (empty ⇒ locked).
        #[arg(value_enum)]
        level: InboundLevel,
    },
    /// Enter the tenant. Two forms: interactive shell, or `-- <cmd>`.
    ///
    /// `tenant shell <name>` (interactive): auto-narrows the firewall
    /// to runtime tier, ensures the host's share-group membership,
    /// reapplies declared `[[shares]]`, then launches a login shell as
    /// the tenant via `sudo -iu <name>`. The login shell inherits the
    /// tenant's `/etc/zprofile` + `~/.zprofile` environment (the host
    /// shell's env vars do NOT propagate — including `SSH_AUTH_SOCK`).
    ///
    /// `tenant shell <name> [--mode install|runtime] -- <cmd...>`
    /// (command form): same reapply at the requested tier (runtime by
    /// default), runs `<cmd...>` as the tenant via `sudo -nu <name>`,
    /// then always reapplies at runtime tier on completion —
    /// guarantees on-disk state returns to runtime even if `--mode
    /// install` widened it. The child's exit code propagates to the
    /// verb's exit. A narrow-on-completion failure emits a warning to
    /// stderr naming `tenant mode <name> runtime` for recovery, but
    /// does NOT override the child's exit code.
    ///
    /// `--mode` / `--inbound` are valid only with `-- <cmd>` — widening
    /// the interactive session would leave the operator at install tier
    /// / permissive inbound silently. The egress (`--mode`) and inbound
    /// (`--inbound`) widenings are orthogonal: each leaves the axis it
    /// doesn't name at steady state, and both narrow back on completion.
    #[command(after_help = "\
Examples:
  tenant shell alice                     enter an interactive login shell
  tenant shell alice -- ls /tmp          run one command at runtime tier
  tenant shell alice --mode install -- pip install foo
                                         widen egress for the call, narrow on completion
  tenant shell alice --inbound permissive -- gh auth login
                                         widen inbound loopback for the call, narrow on completion")]
    Shell {
        /// Tenant short username.
        name: TenantUserName,
        /// Firewall tier for the command-form reapply. `install` widens
        /// egress for the call; runtime narrow always fires on completion.
        /// Requires `-- <cmd>` — rejected on the interactive form.
        #[arg(long, value_enum, requires = "argv")]
        mode: Option<ModeLevel>,
        /// Inbound loopback posture for the command-form reapply.
        /// `permissive` opens all inbound loopback TCP for the call; the
        /// restricted narrow always fires on completion. Requires
        /// `-- <cmd>` — rejected on the interactive form (which
        /// auto-narrows inbound to restricted on entry). Orthogonal to
        /// `--mode`: widening inbound leaves egress at runtime tier.
        #[arg(long, value_enum, requires = "argv")]
        inbound: Option<InboundLevel>,
        /// Command to run as the tenant (everything after `--`). Empty
        /// argv selects the interactive login-shell form.
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Audit host + tenant state read-only. Bare form walks every tenant.
    ///
    /// Probes sensitive host paths as each tenant (via `sudo -n -u
    /// <name> /bin/test ...`) and treats the kernel's exit code as
    /// ground truth — composes POSIX + ACL + sandbox + TCC without
    /// a separate effective-access model. Also checks host-wide PF
    /// posture, sudo `env_delete` protection, the PF anchor body
    /// against the profile, and per-tenant share drift.
    ///
    /// Bare `tenant doctor` walks every tenant. `--strict` maps the
    /// maximum severity to a non-zero exit (1 on warnings, 2 on any
    /// critical finding); without `--strict`, doctor's contract is
    /// informational and exits 0. Requires admin-group membership;
    /// doctor caches one sudo session up front so subsequent probes
    /// run silently.
    Doctor {
        /// Optional tenant short username. Omit to audit every tenant
        /// on the host.
        name: Option<TenantUserName>,
        /// Exit 1 if any warning surfaces, 2 if any critical finding
        /// surfaces. Default exits 0 regardless (findings still print).
        #[arg(long)]
        strict: bool,
    },
    /// Long-form topic help (e.g. `tenant help profile`).
    ///
    /// Renders a topic body to stdout. `profile` covers the per-tenant
    /// profile TOML schema and `[[shares]]` format. Future topics will
    /// follow the same shape. Omit the topic to list available topics.
    Help {
        /// Topic to render. Omit to list available topics.
        #[arg(value_enum)]
        topic: Option<HelpTopic>,
    },
}

/// Which tier of the profile's allowlist the rendered firewall anchor
/// includes. Runtime is the baseline; install is the widened set.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ModeLevel {
    Runtime,
    Install,
}

impl ModeLevel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ModeLevel::Runtime => "runtime",
            ModeLevel::Install => "install",
        }
    }
}

/// The per-tenant inbound loopback posture. `restricted` (the default)
/// gates inbound loopback TCP on the profile's declared `[inbound]` ports
/// (empty ⇒ locked); `permissive` is the temporary all-ports widen.
/// Parallel to `ModeLevel` on a second, orthogonal axis.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum InboundLevel {
    Restricted,
    Permissive,
}

impl InboundLevel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            InboundLevel::Restricted => "restricted",
            InboundLevel::Permissive => "permissive",
        }
    }
}

/// Topics renderable by `tenant help <topic>`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum HelpTopic {
    /// Per-tenant profile TOML schema and `[[shares]]` format.
    Profile,
}
