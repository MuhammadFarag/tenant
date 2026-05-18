//! PF anchor + `/etc/pf.conf` line ops. Pure functions; the substrate's
//! `MacosHostMachine::execute_firewall` calls them indirectly via the
//! `FirewallOp::InstallAnchor.body` / `UpdateConfig.content` payloads
//! that the Writer composes at create/destroy time.
//!
//! The free-function shape (not methods on `FirewallOp`) keeps these
//! ops content-shapers — they don't know about the substrate, just
//! about PF syntax. The Writer threads parsed profile data → anchor
//! body / updated conf content → `FirewallOp` payloads.

/// Absolute directory housing per-tenant PF anchor files. The
/// `load anchor … from "<path>"` line in `/etc/pf.conf` embeds this
/// path, and `MacosHostMachine::execute_firewall` will write/remove
/// files under it. Public because `ensure_anchor_ref`'s rendered
/// output exposes the path and tests want a single source of truth.
pub const ANCHOR_DIR: &str = "/etc/pf.anchors";

/// The host's PF configuration file. The Writer reads this via
/// `HostMachine::read_pf_conf`, edits with `ensure_anchor_ref` /
/// `remove_anchor_ref`, and writes back via
/// `FirewallOp::UpdateConfig`.
pub const PF_CONF: &str = "/etc/pf.conf";

/// Fixed-name backup of `/etc/pf.conf`. Created by
/// `FirewallOp::BackupConfig` before any edit; restored by
/// `FirewallOp::RestoreConfigFromBackup` on reload failure.
/// Overwritten on each create/destroy invocation (deterministic
/// recovery; no timestamped backups). Named with the `tenant-` prefix
/// so a coexisting host backup convention (e.g. `pf.conf.bak`) stays
/// distinct.
pub const PF_CONF_BACKUP: &str = "/etc/pf.conf.tenant-backup";

/// Absolute path of `tenant-<name>`'s anchor file under `ANCHOR_DIR`.
/// Helper for substrate paths (the describe-arm line is constructed
/// from this convention but stays as a literal so a future path move
/// doesn't silently desync display from execution).
pub fn tenant_anchor_path(name: &str) -> String {
    format!("{ANCHOR_DIR}/{}", tenant_anchor_name(name))
}

/// The full PF anchor name for a tenant. `tenant_share_group_name`
/// centralizes the `<name>-tenant-share` suffix for groups; this is
/// the symmetric centralization for the `tenant-<name>` prefix on
/// anchors. Single source of truth so callers can't drift.
pub fn tenant_anchor_name(name: &str) -> String {
    format!("tenant-{name}")
}

fn anchor_line(anchor: &str) -> String {
    format!("anchor \"{anchor}\"")
}

fn load_anchor_line(anchor: &str) -> String {
    format!("load anchor \"{anchor}\" from \"{ANCHOR_DIR}/{anchor}\"")
}

/// `true` iff both the `anchor` and `load anchor` lines for tenant
/// `name` are present in `content`. Line-level (not substring): the
/// bare `anchor "X"` line is a substring of `load anchor "X" from …`,
/// so a substring check would falsely report the anchor line as
/// present when only the load line exists, and the rules wouldn't
/// actually be installed.
pub fn is_anchor_referenced(content: &str, name: &str) -> bool {
    let anchor = tenant_anchor_name(name);
    let target_anchor = anchor_line(&anchor);
    let target_load = load_anchor_line(&anchor);
    let mut has_anchor = false;
    let mut has_load = false;
    for line in content.lines() {
        if line == target_anchor {
            has_anchor = true;
        } else if line == target_load {
            has_load = true;
        }
    }
    has_anchor && has_load
}

/// Return `content` with both anchor + load-anchor lines for tenant
/// `name` ensured present. Idempotent: if both are already there,
/// returns the input verbatim. If one is missing, appends only the
/// missing line(s) — never duplicates. Preserves existing trailing
/// newline conventions.
pub fn ensure_anchor_ref(content: &str, name: &str) -> String {
    let anchor = tenant_anchor_name(name);
    let target_anchor = anchor_line(&anchor);
    let target_load = load_anchor_line(&anchor);
    let mut has_anchor = false;
    let mut has_load = false;
    for line in content.lines() {
        if line == target_anchor {
            has_anchor = true;
        } else if line == target_load {
            has_load = true;
        }
    }
    if has_anchor && has_load {
        return content.to_string();
    }
    // Normalize trailing newline state so appended lines land cleanly.
    let mut out = content.trim_end_matches('\n').to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    if !has_anchor {
        out.push_str(&target_anchor);
        out.push('\n');
    }
    if !has_load {
        out.push_str(&target_load);
        out.push('\n');
    }
    out
}

/// Return `content` with both anchor + load-anchor lines for tenant
/// `name` removed. Idempotent: absent lines silently no-op (mirrors
/// `rm -f` semantics for the file side of the op).
pub fn remove_anchor_ref(content: &str, name: &str) -> String {
    let anchor = tenant_anchor_name(name);
    let target_anchor = anchor_line(&anchor);
    let target_load = load_anchor_line(&anchor);
    let mut out = String::new();
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n');
        if trimmed != target_anchor && trimmed != target_load {
            out.push_str(line);
        }
    }
    out
}

/// Render the PF anchor body for the named tenant with the given runtime
/// hosts. Output is the verbatim file content for
/// `/etc/pf.anchors/tenant-<name>`. Mirrors the sandbox plugin's
/// `pf.py::render_anchor` shape:
///
/// 1. Header comment naming the tenant.
/// 2. `table <allowed> persist { … }` — backslash-continued when
///    populated, single-line `{ }` when empty.
/// 3. `pass out quick on lo0 user <name>` — loopback MUST come before
///    the catchall block (without this, tenants can't reach localhost
///    services like a host-run MySQL or Redis).
/// 4. `pass out quick proto tcp from any to <allowed> port 443 user <name>`
///    — the actual egress allowlist gate.
/// 5. `block out quick proto { tcp udp } from any to any user <name>`
///    — catchall scoped to the tenant's UID via PF's `user` keyword.
///
/// Host order is preserved from `hosts` so the rendered anchor's diff is
/// stable against the operator's profile.toml grouping.
pub fn render_anchor(name: &str, hosts: &[String]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# PF anchor for tenant '{name}' \u{2014} generated by 'tenant create'; do not edit by hand\n\n"
    ));
    if hosts.is_empty() {
        out.push_str("table <allowed> persist { }\n");
    } else {
        out.push_str("table <allowed> persist { \\\n");
        for host in hosts {
            out.push_str(&format!("  {host} \\\n"));
        }
        out.push_str("}\n");
    }
    out.push('\n');
    out.push_str(&format!("pass out quick on lo0 user {name}\n"));
    out.push_str(&format!(
        "pass out quick proto tcp from any to <allowed> port 443 user {name}\n"
    ));
    out.push_str(&format!(
        "block out quick proto {{ tcp udp }} from any to any user {name}\n"
    ));
    out
}
