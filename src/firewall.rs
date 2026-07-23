//! PF anchor + `/etc/pf.conf` line ops. Pure functions over PF syntax.

pub const ANCHOR_DIR: &str = "/etc/pf.anchors";

pub const PF_CONF: &str = "/etc/pf.conf";

/// Fixed-name backup of `/etc/pf.conf`. Overwritten on each invocation
/// (deterministic recovery; no timestamped backups). The `tenant-`
/// prefix keeps it distinct from any host backup convention (e.g.
/// `pf.conf.bak`).
pub const PF_CONF_BACKUP: &str = "/etc/pf.conf.tenant-backup";

pub fn tenant_anchor_path(name: &str) -> String {
    format!("{ANCHOR_DIR}/{}", tenant_anchor_name(name))
}

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
/// present when only the load line exists.
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
/// `name` ensured present. Idempotent; appends only missing line(s).
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
/// `name` removed. Idempotent; absent lines silently no-op.
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

/// The inbound loopback posture for a tenant, resolved in the domain
/// layer (`cli::InboundLevel` + the profile's declared ports) before the
/// pure renderer sees it — exactly as egress hosts are resolved to a
/// `&[EgressHost]` before `render_anchor`. Keeps `firewall.rs` free of any
/// `cli` dependency.
///
/// `Permissive` is the temporary all-ports widen; `Restricted(ports)` is
/// the default deny-by-default surface, with an empty `ports` meaning
/// locked (no inbound from anyone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundRules {
    Permissive,
    Restricted(Vec<u16>),
}

/// An egress allowlist entry resolved for the renderer: a host plus the
/// TCP ports it may be reached on. The domain (`hosts_for_level`) resolves
/// profile entries into `Vec<EgressHost>` before `render_anchor` sees them
/// — exactly how `InboundRules` is resolved from the profile — so
/// `firewall.rs` stays free of any `profile`/`cli` dependency. A bare
/// profile host resolves to `ports = [443]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressHost {
    pub host: String,
    pub ports: Vec<u16>,
}

/// The default egress port group. A profile's bare hosts (and any entry
/// declaring exactly `[443]`) render into the `<allowed>` table + the
/// `port 443` rule — today's shape — which is what buys byte-identity for
/// every pre-ports profile.
const DEFAULT_PORTS: &[u16] = &[443];

/// Render the PF anchor body for the named tenant with the given runtime
/// hosts + inbound posture. Output is the verbatim file content for
/// `/etc/pf.anchors/tenant-<name>`:
///
/// 1. Header comment naming the tenant.
/// 2. One `table <…> persist { … }` per egress port group (pf tables
///    can't carry ports). The `[443]` DEFAULT group renders first, always,
///    as `table <allowed> persist { … }` (backslash-continued when
///    populated, single-line `{ }` when empty) — this is what buys
///    byte-identity for a bare-only / empty profile. Other groups follow
///    in first-occurrence order, table `allowed_<ports joined by _>` (e.g.
///    `<allowed_443_22>`). All tables render here at the top (pf requires
///    definition before use).
/// 3. The inbound loopback section (`inbound` posture; see below). The
///    `pass out … no state` half MUST come before the catchall block
///    (without it tenants can't reach localhost services like a host-run
///    MySQL or Redis).
/// 4. `pass out quick proto tcp from any to <allowed> port 443 user <name>`
///    — the default group's egress gate, always rendered first; then one
///    `pass out … to <allowed_…> port <spec> …` per other group in
///    first-occurrence order.
/// 5. `block out quick proto { tcp udp } from any to any user <name>`
///    — catchall scoped to the tenant's UID via PF's `user` keyword.
///
/// The inbound section takes one of three forms:
/// - `Restricted` with non-empty ports: a `pass in … port <P> … no state`
///   for the declared ports, then `block drop in … flags S/SA`, then the
///   `pass out … no state` egress.
/// - `Restricted` with empty ports (LOCKED): omit the inbound pass; emit
///   only the `block drop in` + the `pass out … no state` egress.
/// - `Permissive`: a single `pass quick on lo0 … no state` replacing the
///   whole section.
///
/// The egress `pass out … no state` is load-bearing: a declared port's
/// reply path depends on `no state` (the auto `keep state` would re-derive
/// from the egress and break the restricted-port reply). `block drop in`
/// keeps `flags S/SA` so the tenant's own outbound-reply packets (SYN+ACK
/// on a connection it initiated) aren't caught.
///
/// Host order is preserved from `hosts`, port-group order is
/// first-occurrence, and the port list within a group is verbatim (so
/// `[443, 22]` and `[22, 443]` are distinct groups) — the rendered
/// anchor's diff stays stable against the operator's profile.toml grouping.
pub fn render_anchor(name: &str, hosts: &[EgressHost], inbound: InboundRules) -> String {
    // Default-group hosts (ports == [443]) in declared order, plus every
    // other port group in first-occurrence order with its hosts in
    // declared order.
    let default_hosts: Vec<&str> = hosts
        .iter()
        .filter(|h| h.ports.as_slice() == DEFAULT_PORTS)
        .map(|h| h.host.as_str())
        .collect();
    let mut other_groups: Vec<(&[u16], Vec<&str>)> = Vec::new();
    for h in hosts {
        if h.ports.as_slice() == DEFAULT_PORTS {
            continue;
        }
        match other_groups
            .iter_mut()
            .find(|(p, _)| *p == h.ports.as_slice())
        {
            Some((_, group_hosts)) => group_hosts.push(h.host.as_str()),
            None => other_groups.push((h.ports.as_slice(), vec![h.host.as_str()])),
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "# PF anchor for tenant '{name}' \u{2014} generated by 'tenant create'; do not edit by hand\n\n"
    ));
    // Tables first: the default `<allowed>` table always, then each other
    // group's table (pf requires table definition before use).
    push_table(&mut out, "allowed", &default_hosts);
    for (ports, group_hosts) in &other_groups {
        push_table(&mut out, &table_name(ports), group_hosts);
    }
    out.push('\n');
    out.push_str(&render_inbound_section(name, &inbound));
    // Default group's gate always first (byte-identity), then each other
    // group's gate before the catchall.
    out.push_str(&format!(
        "pass out quick proto tcp from any to <allowed> port 443 user {name}\n"
    ));
    for (ports, _) in &other_groups {
        out.push_str(&format!(
            "pass out quick proto tcp from any to <{}> port {} user {name}\n",
            table_name(ports),
            render_port_spec(ports),
        ));
    }
    out.push_str(&format!(
        "block out quick proto {{ tcp udp }} from any to any user {name}\n"
    ));
    out
}

/// Push a `table <name> persist { … }` block: single-line `{ }` when
/// empty, else backslash-continued one host per line. Shared by the
/// default group and every port group.
fn push_table(out: &mut String, table: &str, hosts: &[&str]) {
    if hosts.is_empty() {
        out.push_str(&format!("table <{table}> persist {{ }}\n"));
    } else {
        out.push_str(&format!("table <{table}> persist {{ \\\n"));
        for host in hosts {
            out.push_str(&format!("  {host} \\\n"));
        }
        out.push_str("}\n");
    }
}

/// Table name for a non-default port group: `allowed_<ports joined by _>`
/// in the group's verbatim port order (`[443, 22]` ⇒ `allowed_443_22`).
fn table_name(ports: &[u16]) -> String {
    let joined = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("_");
    format!("allowed_{joined}")
}

/// `true` iff `body` is in the permissive inbound posture — i.e. it
/// carries the collapsed `pass quick on lo0 … no state` line (no
/// `in`/`out` direction keyword) that `render_inbound_section` emits
/// only for `InboundRules::Permissive`. Doctor reads the on-disk anchor
/// to learn the CURRENT inbound posture (there's no state file); a
/// permissive anchor is the one widened form to flag.
///
/// Structural, not byte-exact: the renderer is deterministic, but a
/// hand-edit could re-order or re-space lines, so match the permissive
/// line's presence rather than the whole body. The restricted/locked
/// forms always write a directioned `pass in`/`pass out` line, never the
/// directionless collapsed form, so there's no overlap.
pub fn anchor_is_permissive(body: &str) -> bool {
    let needle = "pass quick on lo0 proto tcp from any to any";
    body.lines()
        .any(|line| line.trim_start().starts_with(needle))
}

/// Render the loopback section for the given inbound posture. See
/// `render_anchor` for the three forms.
fn render_inbound_section(name: &str, inbound: &InboundRules) -> String {
    match inbound {
        InboundRules::Permissive => {
            format!("pass quick on lo0 proto tcp from any to any user {name} no state\n")
        }
        InboundRules::Restricted(ports) => {
            let mut section = String::new();
            if !ports.is_empty() {
                section.push_str(&format!(
                    "pass in quick on lo0 proto tcp from any to any port {} user {name} no state\n",
                    render_port_spec(ports)
                ));
            }
            section.push_str(&format!(
                "block drop in quick on lo0 proto tcp from any to any user {name} flags S/SA\n"
            ));
            section.push_str(&format!(
                "pass out quick on lo0 proto tcp from any to any user {name} no state\n"
            ));
            section
        }
    }
}

/// Render a port list as a pf port spec: a single port renders bare
/// (`3000`); multiple render as a pf list (`{ 3000, 8080 }`). Order is
/// preserved from the caller. Caller guarantees non-empty.
fn render_port_spec(ports: &[u16]) -> String {
    if ports.len() == 1 {
        ports[0].to_string()
    } else {
        let joined = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{ {joined} }}")
    }
}
