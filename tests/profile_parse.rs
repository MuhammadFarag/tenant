//! Combinatorial coverage on `profile::parse`. Tests the free-function
//! parser directly because no verb wires the read+parse path until 2.4
//! (create-side firewall step), and the matrix here is parser-state-shaped
//! (schema version × structural completeness × TOML well-formedness) which
//! is awkward to drive through the CLI surface. Same in-tree precedent
//! and justification as `tests/macos_host_machine.rs`'s per-variant pins on
//! `MacosHostMachine::describe_*`.

use std::path::PathBuf;

use tenant::profile::{
    Allowlist, Bootstrap, HostEntry, Inbound, PartialProfile, Profile, ProfileRole, Share,
    ShareMode, Tier, default_profile_toml, expand_tenant_path, merge, parse, parse_partial,
};

// A bare profile host resolves to TCP 443 — the pre-ports meaning.
fn bare(host: &str) -> HostEntry {
    HostEntry {
        host: host.to_string(),
        ports: vec![443],
    }
}

#[test]
fn parse_default_toml_yields_schema_1_with_empty_allowlists() {
    let profile = parse(&default_profile_toml()).expect("default toml must parse");
    assert_eq!(
        profile,
        Profile {
            schema_version: 1,
            allowlist: Allowlist {
                runtime: Tier { hosts: vec![] },
                install: Tier { hosts: vec![] },
            },
            shares: vec![],
            inbound: Inbound { ports: vec![] },
            bootstrap: Bootstrap { commands: vec![] },
        }
    );
}

#[test]
fn parse_populated_runtime_hosts_preserves_input_order() {
    // Hand-rolled TOML (not via serde::to_string) so we pin the wire
    // format the operator edits. Order matters: the operator groups
    // hosts in profile.toml in a meaningful order (e.g. provider,
    // ecosystem) and `render_anchor` later emits them in the same order
    // for diff stability.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [\"api.anthropic.com\", \"github.com\", \"crates.io\"]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let profile = parse(toml).expect("must parse");
    assert_eq!(
        profile.allowlist.runtime.hosts,
        vec![
            bare("api.anthropic.com"),
            bare("github.com"),
            bare("crates.io"),
        ]
    );
}

#[test]
fn parse_populated_install_hosts_preserves_input_order() {
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = [\"registry.npmjs.org\", \"pypi.org\"]\n";
    let profile = parse(toml).expect("must parse");
    assert_eq!(
        profile.allowlist.install.hosts,
        vec![bare("registry.npmjs.org"), bare("pypi.org")]
    );
}

#[test]
fn parse_refuses_schema_version_2_with_operator_readable_message() {
    let toml = "schema_version = 2\n\
                \n\
                [allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let err = parse(toml).expect_err("schema_version 2 must be refused");
    assert_eq!(
        err.message,
        "schema_version 2 not understood (this tenant supports 1)"
    );
}

#[test]
fn parse_refuses_missing_schema_version() {
    let toml = "[allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let err = parse(toml).expect_err("missing schema_version must be refused");
    // Refused by merge's completeness check: schema_version is optional in
    // a PartialProfile but must be present in the merged result. The
    // dispatcher's Reporter call wraps this in the path-naming frame so the
    // operator gets full context end-to-end.
    assert!(
        err.message.contains("schema_version"),
        "expected message to mention schema_version, got: {}",
        err.message
    );
}

#[test]
fn parse_refuses_missing_allowlist_section() {
    let toml = "schema_version = 1\n";
    let err = parse(toml).expect_err("missing allowlist must be refused");
    assert!(
        err.message.contains("allowlist"),
        "expected message to mention allowlist, got: {}",
        err.message
    );
}

#[test]
fn parse_refuses_invalid_toml_syntax() {
    let toml = "this is not valid toml = = =\n";
    let err = parse(toml).expect_err("invalid TOML must be refused");
    assert!(
        err.message.starts_with("invalid TOML"),
        "expected 'invalid TOML' prefix, got: {}",
        err.message
    );
}

// --- per-host egress ports ---------------------------------------------
//
// A `hosts` array element is either a bare string (TCP 443 only —
// backward-compat) or an inline `{ host = …, ports = [...] }` table
// declaring that host's TCP ports. Normalized to `HostEntry { host, ports }`
// at parse; `ports = []` is refused (a host with no ports is unreachable).

#[test]
fn bare_host_string_resolves_to_port_443() {
    // Backward-compat: a bare string keeps today's meaning (443 only).
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [\"github.com\"]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let profile = parse(toml).expect("must parse");
    assert_eq!(
        profile.allowlist.runtime.hosts,
        vec![HostEntry {
            host: "github.com".to_string(),
            ports: vec![443],
        }]
    );
}

#[test]
fn inline_table_host_round_trips_host_and_ports_in_order() {
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [{ host = \"github.com\", ports = [443, 22] }]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let profile = parse(toml).expect("must parse");
    assert_eq!(
        profile.allowlist.runtime.hosts,
        vec![HostEntry {
            host: "github.com".to_string(),
            ports: vec![443, 22],
        }]
    );
}

#[test]
fn mixed_bare_and_table_array_parses() {
    // The git-over-ssh case (brief example B): a bare host next to an
    // inline-table host in the same array.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [\n\
                  \"api.anthropic.com\",\n\
                  { host = \"github.com\", ports = [443, 22] },\n\
                ]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let profile = parse(toml).expect("must parse");
    assert_eq!(
        profile.allowlist.runtime.hosts,
        vec![
            bare("api.anthropic.com"),
            HostEntry {
                host: "github.com".to_string(),
                ports: vec![443, 22],
            },
        ]
    );
}

#[test]
fn empty_ports_entry_refused_with_byte_exact_message() {
    // Decision 3: a host with no ports is unreachable — refuse at parse,
    // naming the host. Byte-exact message pin.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [{ host = \"github.com\", ports = [] }]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let err = parse(toml).expect_err("empty-ports entry must be refused");
    assert_eq!(
        err.message,
        "allowlist host \"github.com\" declares ports = []; a host with no ports is \
         unreachable \u{2014} remove the entry or declare its ports"
    );
}

#[test]
fn malformed_host_entry_table_missing_host_errors() {
    // A table entry missing `host` is a parse error. serde's untagged
    // enum gives a blunt message — pin only that it errors, not the text.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [{ ports = [443] }]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    parse(toml).expect_err("table entry missing host must be refused");
}

// --- [[shares]] table-array --------------------------------------------
//
// The profile grows an optional table-array declaring per-tenant
// filesystem shares: `(host_path, mode, tenant_path)` triples. Mode is a
// string discriminator (`"ro"` / `"rw"`) — POSIX bit-string forms
// rejected because POSIX bit semantics differ for files vs directories.
// `tenant_path` is stored raw (template form with `$HOME` if used); the
// Tenants struct expands at op-construction time. Backward-compat: missing
// `[[shares]]` array yields an empty Vec.

fn toml_with_shares_section(shares_body: &str) -> String {
    format!(
        "schema_version = 1\n\
         \n\
         [allowlist.runtime]\n\
         hosts = []\n\
         \n\
         [allowlist.install]\n\
         hosts = []\n\
         \n\
         {shares_body}"
    )
}

#[test]
fn parses_share_entry_with_rw_mode() {
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/Users/Shared/sandbox/dev\"\n\
         mode = \"rw\"\n\
         tenant_path = \"/Users/dev/src\"\n",
    );
    let profile = parse(&toml).expect("must parse");
    assert_eq!(
        profile.shares,
        vec![Share {
            host_path: PathBuf::from("/Users/Shared/sandbox/dev"),
            mode: ShareMode::Rw,
            tenant_path: "/Users/dev/src".to_string(),
        }]
    );
}

#[test]
fn parses_share_entry_with_ro_mode() {
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/Users/Shared/dotfiles\"\n\
         mode = \"ro\"\n\
         tenant_path = \"/Users/dev/.local/share/chezmoi\"\n",
    );
    let profile = parse(&toml).expect("must parse");
    assert_eq!(
        profile.shares,
        vec![Share {
            host_path: PathBuf::from("/Users/Shared/dotfiles"),
            mode: ShareMode::Ro,
            tenant_path: "/Users/dev/.local/share/chezmoi".to_string(),
        }]
    );
}

#[test]
fn parses_multiple_share_entries_preserves_declared_order() {
    // Profile-declared order, not alphabetical-by-host-path. Same
    // convention as `allowlist.runtime.hosts`. Operator-readable;
    // order doesn't affect correctness (idempotent substrate) —
    // preserving intent is the small win.
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/Users/Shared/zeta\"\n\
         mode = \"rw\"\n\
         tenant_path = \"/Users/dev/zeta\"\n\
         \n\
         [[shares]]\n\
         host_path = \"/Users/Shared/alpha\"\n\
         mode = \"ro\"\n\
         tenant_path = \"/Users/dev/alpha\"\n",
    );
    let profile = parse(&toml).expect("must parse");
    let host_paths: Vec<&PathBuf> = profile.shares.iter().map(|s| &s.host_path).collect();
    assert_eq!(
        host_paths,
        vec![
            &PathBuf::from("/Users/Shared/zeta"),
            &PathBuf::from("/Users/Shared/alpha"),
        ]
    );
}

#[test]
fn parses_share_entry_with_home_prefixed_tenant_path() {
    // `$HOME` is the only template variable; expansion happens in
    // the Tenants struct when it resolves the share entry. The parser stores
    // the raw string so the type itself signals "this is a template,
    // not yet resolved" — a substrate call against a raw template
    // would be a type mistake at construction time.
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/Users/Shared/sandbox/dev\"\n\
         mode = \"rw\"\n\
         tenant_path = \"$HOME/src\"\n",
    );
    let profile = parse(&toml).expect("must parse");
    assert_eq!(profile.shares[0].tenant_path, "$HOME/src");
}

#[test]
fn absent_shares_array_yields_empty_vec() {
    // Backward-compat: profiles written before the share substrate
    // shipped have no `[[shares]]` section. Parse must succeed and
    // yield an empty Vec so older profiles keep working.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let profile = parse(toml).expect("must parse without shares section");
    assert!(
        profile.shares.is_empty(),
        "expected empty shares Vec, got: {:?}",
        profile.shares
    );
}

#[test]
fn unknown_mode_value_rejected() {
    // Only `"ro"` and `"rw"` accepted. POSIX bit-string forms
    // (`"r"`, `"rwe"`, etc.) and uppercase variants all fail parse.
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/Users/Shared/sandbox/dev\"\n\
         mode = \"rwx\"\n\
         tenant_path = \"/Users/dev/src\"\n",
    );
    let err = parse(&toml).expect_err("unknown mode value must be refused");
    assert!(
        err.message.contains("mode") || err.message.contains("rwx"),
        "expected message to mention mode or the bad value, got: {}",
        err.message
    );
}

#[test]
fn missing_host_path_rejected() {
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         mode = \"rw\"\n\
         tenant_path = \"/Users/dev/src\"\n",
    );
    let err = parse(&toml).expect_err("missing host_path must be refused");
    assert!(
        err.message.contains("host_path"),
        "expected message to mention host_path, got: {}",
        err.message
    );
}

#[test]
fn missing_mode_rejected() {
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/Users/Shared/sandbox/dev\"\n\
         tenant_path = \"/Users/dev/src\"\n",
    );
    let err = parse(&toml).expect_err("missing mode must be refused");
    assert!(
        err.message.contains("mode"),
        "expected message to mention mode, got: {}",
        err.message
    );
}

// --- expand_tenant_path -----------------------------------------------
//
// `$HOME` is the only template variable. The Tenants struct expands it to
// `/Users/<tenant>` at op-construction time; the substrate sees
// absolute paths. Literal absolute paths flow through unchanged.

#[test]
fn expand_tenant_path_with_home_subpath() {
    assert_eq!(
        expand_tenant_path("dev", "$HOME/src"),
        PathBuf::from("/Users/dev/src")
    );
}

#[test]
fn expand_tenant_path_with_nested_home_subpath() {
    assert_eq!(
        expand_tenant_path("dev", "$HOME/.local/share/chezmoi"),
        PathBuf::from("/Users/dev/.local/share/chezmoi")
    );
}

#[test]
fn expand_tenant_path_bare_home_is_tenant_home_dir() {
    assert_eq!(
        expand_tenant_path("dev", "$HOME"),
        PathBuf::from("/Users/dev")
    );
}

#[test]
fn expand_tenant_path_literal_absolute_passes_through() {
    // No `$HOME` prefix: keep the literal absolute path. Operator's
    // declaration is what the substrate sees.
    assert_eq!(
        expand_tenant_path("dev", "/opt/shared"),
        PathBuf::from("/opt/shared")
    );
}

#[test]
fn expand_tenant_path_does_not_expand_mid_string_home() {
    // `$HOME` is a prefix marker, not a free-text substitution.
    // (Parse-time validation refuses mid-string $HOME; this test
    // pins the expansion function's behavior IF a mid-string value
    // got past parse — defense in depth at the substrate.)
    assert_eq!(
        expand_tenant_path("dev", "/etc/$HOME/foo"),
        PathBuf::from("/etc/$HOME/foo")
    );
}

// --- $HOME prefix-only validation -------------------------------------
//
// `parse` refuses any tenant_path containing `$HOME` not at position 0
// (followed by `/` or as the whole path). Catches operator typos like
// `$HOME$HOME/src` that would silently expand to weird literal paths.

#[test]
fn parse_refuses_tenant_path_with_double_home() {
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/tmp\"\n\
         mode = \"rw\"\n\
         tenant_path = \"$HOME$HOME/src\"\n",
    );
    let err = parse(&toml).expect_err("double-$HOME must be refused");
    assert!(
        err.message.contains("$HOME"),
        "expected message to mention $HOME: {}",
        err.message
    );
    assert!(
        err.message.contains("$HOME$HOME/src") || err.message.contains("not at the start"),
        "expected message to name the value or the rule: {}",
        err.message
    );
}

#[test]
fn parse_refuses_tenant_path_with_mid_string_home() {
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/tmp\"\n\
         mode = \"rw\"\n\
         tenant_path = \"/etc/$HOME/foo\"\n",
    );
    let err = parse(&toml).expect_err("mid-string $HOME must be refused");
    assert!(
        err.message.contains("$HOME"),
        "expected message to mention $HOME: {}",
        err.message
    );
}

#[test]
fn parse_accepts_tenant_path_bare_home() {
    // `$HOME` alone (no slash) IS valid — expands to /Users/<name>.
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/tmp\"\n\
         mode = \"rw\"\n\
         tenant_path = \"$HOME\"\n",
    );
    parse(&toml).expect("bare $HOME must parse");
}

#[test]
fn missing_tenant_path_rejected() {
    let toml = toml_with_shares_section(
        "[[shares]]\n\
         host_path = \"/Users/Shared/sandbox/dev\"\n\
         mode = \"rw\"\n",
    );
    let err = parse(&toml).expect_err("missing tenant_path must be refused");
    assert!(
        err.message.contains("tenant_path"),
        "expected message to mention tenant_path, got: {}",
        err.message
    );
}

// --- [inbound] section -------------------------------------------------
//
// The profile grows an optional `[inbound]` table declaring the TCP
// loopback ports the tenant exposes under the default `restricted`
// posture: `ports = [<u16> ...]`. No proto field (TCP only — UDP
// loopback is unfiltered). Absent section / empty list both mean
// "locked" (no inbound pass emitted). Same backward-compat posture as
// `[[shares]]`: missing section deserializes to an empty Vec.

fn toml_with_inbound_section(inbound_body: &str) -> String {
    format!(
        "schema_version = 1\n\
         \n\
         [allowlist.runtime]\n\
         hosts = []\n\
         \n\
         [allowlist.install]\n\
         hosts = []\n\
         \n\
         {inbound_body}"
    )
}

#[test]
fn parses_inbound_ports_to_u16_in_declared_order() {
    let toml = toml_with_inbound_section("[inbound]\nports = [3000, 8080, 443]\n");
    let profile = parse(&toml).expect("must parse");
    assert_eq!(profile.inbound.ports, vec![3000u16, 8080, 443]);
}

#[test]
fn parses_single_inbound_port() {
    let toml = toml_with_inbound_section("[inbound]\nports = [5173]\n");
    let profile = parse(&toml).expect("must parse");
    assert_eq!(profile.inbound.ports, vec![5173u16]);
}

#[test]
fn absent_inbound_section_yields_empty_ports() {
    // Backward-compat: profiles written before the inbound axis shipped
    // have no `[inbound]` section. Parse must succeed and yield an empty
    // Vec — the locked posture.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let profile = parse(toml).expect("must parse without inbound section");
    assert!(
        profile.inbound.ports.is_empty(),
        "expected empty inbound ports, got: {:?}",
        profile.inbound.ports
    );
}

#[test]
fn empty_inbound_ports_list_yields_empty_ports() {
    let toml = toml_with_inbound_section("[inbound]\nports = []\n");
    let profile = parse(&toml).expect("must parse");
    assert!(
        profile.inbound.ports.is_empty(),
        "expected empty inbound ports, got: {:?}",
        profile.inbound.ports
    );
}

#[test]
fn inbound_port_above_u16_max_rejected() {
    // 70000 > 65535; serde u16 deserialize rejects it. Catches operator
    // typos that would otherwise render an out-of-range pf port.
    let toml = toml_with_inbound_section("[inbound]\nports = [70000]\n");
    let err = parse(&toml).expect_err("out-of-u16 port must be refused");
    assert!(
        err.message.contains("ports") || err.message.contains("70000"),
        "expected message to mention ports or the bad value, got: {}",
        err.message
    );
}

#[test]
fn inbound_non_integer_port_rejected() {
    let toml = toml_with_inbound_section("[inbound]\nports = [\"3000\"]\n");
    let err = parse(&toml).expect_err("non-integer port must be refused");
    assert!(
        err.message.contains("ports") || err.message.contains("integer"),
        "expected message to mention ports or integer, got: {}",
        err.message
    );
}

#[test]
fn default_profile_toml_parses_with_empty_inbound_ports() {
    // The scaffolded `[inbound]` block is fully commented (example port
    // commented out) so it parses to the locked posture.
    let profile = parse(&default_profile_toml()).expect("default toml must parse");
    assert!(
        profile.inbound.ports.is_empty(),
        "expected default profile to have empty inbound ports, got: {:?}",
        profile.inbound.ports
    );
}

#[test]
fn default_profile_toml_carries_commented_include_hint() {
    // Scaffold gains a COMMENTED `# include = ["base"]` hint naming the
    // includes/ subdirectory. Commented, not active: an active include
    // would fail every real `tenant create` — the post-provision
    // load_profile would resolve read_profile_fragment("base") against a
    // not-yet-created includes/base.toml and hard-fail (EX_IOERR).
    // Value-identity of the parsed default is pinned by the two
    // default_profile_toml tests above.
    let toml = default_profile_toml();
    assert!(
        toml.contains("# include = [\"base\"]"),
        "scaffold must carry the commented include hint; got:\n{toml}"
    );
    assert!(
        toml.contains("includes/"),
        "hint must name the includes/ subdirectory; got:\n{toml}"
    );
    // Commented ⇒ the parsed default declares no includes.
    let partial = parse_partial(&toml, ProfileRole::Tenant).expect("default must parse");
    assert!(
        partial.include.is_empty(),
        "the include hint must stay commented (no active include); got {:?}",
        partial.include
    );
}

// --- include fragments: PartialProfile / parse_partial / merge ---------
//
// Half 1 of "Common configuration": a profile may declare
// `include = ["base"]` — an ordered list of fragment names resolved from
// `profiles/includes/<name>.toml`. `PartialProfile` is the wire shape for
// BOTH tenant profiles and fragments (every section optional). `merge`
// folds parts fragments-first + profile-last into the validated `Profile`
// everyone downstream already consumes. `parse` becomes the no-fragments
// composition of the two (value-identical for include-free profiles).

#[test]
fn parse_partial_tenant_profile_populates_declared_sections() {
    let p =
        parse_partial(&default_profile_toml(), ProfileRole::Tenant).expect("default must parse");
    assert_eq!(p.schema_version, Some(1));
    assert!(p.include.is_empty());
    assert!(p.allowlist.runtime.is_some());
    assert!(p.allowlist.install.is_some());
}

#[test]
fn parse_partial_fragment_may_omit_schema_and_tiers() {
    // A fragment is a partial profile: every section optional. One tier,
    // no schema_version, is legal here — completeness is a merge concern.
    let frag = "[allowlist.runtime]\nhosts = [\"api.anthropic.com\"]\n";
    let p = parse_partial(frag, ProfileRole::Fragment).expect("partial fragment must parse");
    assert_eq!(p.schema_version, None);
    assert!(p.allowlist.runtime.is_some());
    assert!(p.allowlist.install.is_none());
}

#[test]
fn parse_partial_empty_fragment_is_legal() {
    // An empty fragment is the identity element of the merge.
    let p = parse_partial("", ProfileRole::Fragment).expect("empty fragment must parse");
    assert_eq!(p, PartialProfile::default());
}

#[test]
fn parse_partial_fragment_declaring_include_is_refused() {
    // Depth one: `include` inside a fragment is refused at parse. No
    // nesting ⇒ no cycle detection.
    let frag = "include = [\"other\"]\n\
                [allowlist.runtime]\n\
                hosts = []\n";
    let err = parse_partial(frag, ProfileRole::Fragment).expect_err("nested include must refuse");
    assert!(
        err.message.contains("fragment") && err.message.contains("include"),
        "message must name fragment+include: {}",
        err.message
    );
}

#[test]
fn parse_partial_fragment_declaring_empty_include_is_refused() {
    // Depth one refuses the presence of the `include` KEY, not just a
    // non-empty list: `include = []` in a fragment still declares include
    // and is a likely authoring mistake (refuse now, not only when the
    // operator later fills it in).
    let frag = "include = []\n\
                [allowlist.runtime]\n\
                hosts = []\n";
    let err = parse_partial(frag, ProfileRole::Fragment)
        .expect_err("empty include in a fragment must refuse");
    assert!(
        err.message.contains("fragment") && err.message.contains("include"),
        "message must name fragment+include: {}",
        err.message
    );
}

#[test]
fn parse_partial_duplicate_include_refused() {
    // Decision 4: a repeated include entry is certainly an authoring
    // mistake — refuse at parse, naming the entry.
    let toml = "schema_version = 1\ninclude = [\"base\", \"base\"]\n";
    let err = parse_partial(toml, ProfileRole::Tenant).expect_err("duplicate include must refuse");
    assert!(
        err.message.contains("base")
            && (err.message.contains("more than once") || err.message.contains("duplicate")),
        "message must name the duplicate: {}",
        err.message
    );
}

#[test]
fn parse_partial_bad_fragment_name_refused() {
    // Decision 1: include entries pass the same lexical rail as tenant
    // names (`[a-z][a-z0-9_-]{0,30}`), foreclosing path traversal without
    // a second charset.
    for bad in ["../etc", "Base", ".hidden", "a/b", "with space", ""] {
        let toml = format!("include = [\"{bad}\"]\n");
        let err = parse_partial(&toml, ProfileRole::Tenant)
            .expect_err(&format!("bad name {bad:?} must be refused"));
        assert!(
            err.message.contains("include name"),
            "bad={bad:?} must be refused naming the entry: {}",
            err.message
        );
    }
}

#[test]
fn parse_partial_fragment_name_length_boundary() {
    // The length rail mirrors validate_name's MAX_NAME_LEN = 31 (total
    // chars): 31 accepted, 32 refused. Pins the off-by-one the plan flagged.
    let ok = "a".repeat(31);
    parse_partial(&format!("include = [\"{ok}\"]\n"), ProfileRole::Tenant)
        .expect("31-char include name must be accepted");
    let too_long = "a".repeat(32);
    let err = parse_partial(
        &format!("include = [\"{too_long}\"]\n"),
        ProfileRole::Tenant,
    )
    .expect_err("32-char include name must be refused");
    assert!(
        err.message.contains("too long"),
        "message must flag length: {}",
        err.message
    );
}

#[test]
fn parse_partial_schema_version_pre_check_runs_per_file() {
    // schema_version is optional in a fragment, but validated against the
    // supported set when present — same pre-check as tenant profiles.
    let frag = "schema_version = 2\n";
    let err = parse_partial(frag, ProfileRole::Fragment).expect_err("schema 2 must refuse");
    assert_eq!(
        err.message,
        "schema_version 2 not understood (this tenant supports 1)"
    );
}

#[test]
fn parse_partial_runs_per_file_ports_and_home_validators() {
    // The existing per-entry validations run per file so a fragment's own
    // mistakes refuse here (the load path names which file).
    let bad_ports = "[allowlist.runtime]\nhosts = [{ host = \"x\", ports = [] }]\n";
    parse_partial(bad_ports, ProfileRole::Fragment).expect_err("ports = [] must refuse");
    let bad_home = "[[shares]]\n\
                    host_path = \"/t\"\n\
                    mode = \"rw\"\n\
                    tenant_path = \"/etc/$HOME/x\"\n";
    parse_partial(bad_home, ProfileRole::Fragment).expect_err("mid-string $HOME must refuse");
    let bad_bootstrap = "[bootstrap]\ncommands = [\"\"]\n";
    parse_partial(bad_bootstrap, ProfileRole::Fragment)
        .expect_err("empty bootstrap command must refuse in a fragment");
}

#[test]
fn merge_unions_runtime_hosts_fragments_first() {
    // Per-tier host lists union in order: fragments first, profile last.
    let frag = parse_partial(
        "[allowlist.runtime]\nhosts = [\"frag.example\"]\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n\
         [allowlist.runtime]\n\
         hosts = [\"prof.example\"]\n\
         [allowlist.install]\n\
         hosts = []\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("must merge");
    assert_eq!(
        merged.allowlist.runtime.hosts,
        vec![bare("frag.example"), bare("prof.example")]
    );
}

#[test]
fn merge_does_not_dedupe_repeated_host() {
    // Decision 3: union = concatenation, no dedupe. A host in both a
    // fragment and the profile renders TWICE (the renderer + pf tables
    // tolerate duplicates); a silent dedup would be invisible to the
    // distinct-host union tests, so pin the duplicate explicitly.
    let frag = parse_partial(
        "[allowlist.runtime]\nhosts = [\"dup.example\"]\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n\
         [allowlist.runtime]\n\
         hosts = [\"dup.example\"]\n\
         [allowlist.install]\n\
         hosts = []\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("must merge");
    assert_eq!(
        merged.allowlist.runtime.hosts,
        vec![bare("dup.example"), bare("dup.example")]
    );
}

#[test]
fn merge_unions_install_hosts_fragments_first() {
    // The install tier is a Tier construction distinct from runtime — pin
    // it independently so a copy-paste bug (e.g. reading `runtime` for
    // both tiers) can't hide behind the runtime-union test above.
    let frag = parse_partial(
        "[allowlist.install]\nhosts = [\"frag.pkg\"]\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n\
         [allowlist.runtime]\n\
         hosts = []\n\
         [allowlist.install]\n\
         hosts = [\"prof.pkg\"]\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("must merge");
    assert_eq!(
        merged.allowlist.install.hosts,
        vec![bare("frag.pkg"), bare("prof.pkg")]
    );
    // Cross-check the tiers didn't bleed: install content stayed out of runtime.
    assert!(merged.allowlist.runtime.hosts.is_empty());
}

#[test]
fn merge_unions_inbound_ports_fragments_first() {
    let frag = parse_partial(
        "[inbound]\nports = [3000]\n[allowlist.runtime]\nhosts = []\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n\
         [allowlist.runtime]\n\
         hosts = []\n\
         [allowlist.install]\n\
         hosts = []\n\
         [inbound]\n\
         ports = [8080]\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("must merge");
    assert_eq!(merged.inbound.ports, vec![3000u16, 8080]);
}

#[test]
fn merge_unions_shares_fragments_first() {
    let frag = parse_partial(
        "[allowlist.runtime]\nhosts = []\n\
         [[shares]]\n\
         host_path = \"/frag\"\n\
         mode = \"ro\"\n\
         tenant_path = \"$HOME/frag\"\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n\
         [allowlist.install]\n\
         hosts = []\n\
         [[shares]]\n\
         host_path = \"/prof\"\n\
         mode = \"rw\"\n\
         tenant_path = \"$HOME/prof\"\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("must merge");
    let host_paths: Vec<&PathBuf> = merged.shares.iter().map(|s| &s.host_path).collect();
    assert_eq!(
        host_paths,
        vec![&PathBuf::from("/frag"), &PathBuf::from("/prof")]
    );
}

#[test]
fn merge_refuses_when_a_tier_is_never_declared() {
    // Merged completeness: both allowlist tiers must be declared somewhere.
    let frag = parse_partial(
        "[allowlist.runtime]\nhosts = [\"x\"]\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n[allowlist.runtime]\nhosts = []\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let err = merge(vec![frag, prof]).expect_err("missing install tier must refuse");
    assert!(
        err.message.contains("allowlist") && err.message.contains("install"),
        "message must name the missing tier: {}",
        err.message
    );
}

#[test]
fn merge_refuses_when_no_schema_version_anywhere() {
    let frag = parse_partial("[allowlist.runtime]\nhosts = []\n", ProfileRole::Fragment).unwrap();
    let prof = parse_partial("[allowlist.install]\nhosts = []\n", ProfileRole::Tenant).unwrap();
    let err = merge(vec![frag, prof]).expect_err("missing schema_version must refuse");
    assert!(
        err.message.contains("schema_version"),
        "message must name schema_version: {}",
        err.message
    );
}

#[test]
fn merge_refuses_verbatim_tenant_path_collision() {
    // Decision 2: the collision compare is verbatim (template strings,
    // byte-for-byte), NOT expanded paths.
    let frag = parse_partial(
        "[allowlist.runtime]\nhosts = []\n\
         [[shares]]\n\
         host_path = \"/a\"\n\
         mode = \"ro\"\n\
         tenant_path = \"$HOME/src\"\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n[allowlist.install]\nhosts = []\n\
         [[shares]]\n\
         host_path = \"/b\"\n\
         mode = \"rw\"\n\
         tenant_path = \"$HOME/src\"\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let err = merge(vec![frag, prof]).expect_err("tenant_path collision must refuse");
    // Byte-exact pin — decision 2's canonical refusal.
    assert_eq!(
        err.message,
        "two shares map to the same tenant_path \"$HOME/src\"; drop the include or \
         inline the share you want"
    );
}

#[test]
fn parse_single_file_duplicate_tenant_path_stays_value_identical() {
    // Value-identity gate (DoD #3): an include-free profile with two shares
    // at the same tenant_path parsed before this feature (no collision
    // check; last-symlink-wins downstream). The collision refusal is a
    // union concern (parts > 1), so `parse` of a single file must NOT
    // acquire a new refusal.
    let toml = "schema_version = 1\n\
                [allowlist.runtime]\n\
                hosts = []\n\
                [allowlist.install]\n\
                hosts = []\n\
                [[shares]]\n\
                host_path = \"/a\"\n\
                mode = \"ro\"\n\
                tenant_path = \"$HOME/src\"\n\
                [[shares]]\n\
                host_path = \"/b\"\n\
                mode = \"rw\"\n\
                tenant_path = \"$HOME/src\"\n";
    let profile = parse(toml).expect("single-file duplicate tenant_path must still parse");
    assert_eq!(profile.shares.len(), 2);
}

#[test]
fn merge_verbatim_collision_ignores_different_spelling() {
    // `$HOME/foo` vs an explicit `/Users/dev/foo` spelling slips through —
    // deterministic, documented, harmless (same class as a host listed twice).
    let frag = parse_partial(
        "[allowlist.runtime]\nhosts = []\n\
         [[shares]]\n\
         host_path = \"/a\"\n\
         mode = \"ro\"\n\
         tenant_path = \"$HOME/foo\"\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n[allowlist.install]\nhosts = []\n\
         [[shares]]\n\
         host_path = \"/b\"\n\
         mode = \"rw\"\n\
         tenant_path = \"/Users/dev/foo\"\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("different spellings must not collide");
    assert_eq!(merged.shares.len(), 2);
}

#[test]
fn merge_include_only_profile_is_legal_when_fragment_complete() {
    // A tenant profile whose only content is `include = ["base"]` is legal
    // if the base is complete.
    let frag = parse_partial(
        "schema_version = 1\n\
         [allowlist.runtime]\n\
         hosts = [\"a\"]\n\
         [allowlist.install]\n\
         hosts = []\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial("include = [\"base\"]\n", ProfileRole::Tenant).unwrap();
    let merged = merge(vec![frag, prof]).expect("include-only profile must merge");
    assert_eq!(merged.schema_version, 1);
    assert_eq!(merged.allowlist.runtime.hosts, vec![bare("a")]);
}

#[test]
fn parse_equals_single_part_merge_for_include_free_profiles() {
    // Backward-compat gate: for an include-free profile, `parse` is
    // value-identical to `merge(vec![parse_partial(..)])` — the no-fragments
    // composition. `Profile` equality ⇒ anchor byte-identity downstream.
    let toml = "schema_version = 1\n\
                [allowlist.runtime]\n\
                hosts = [\"a\"]\n\
                [allowlist.install]\n\
                hosts = [\"b\"]\n";
    let via_parse = parse(toml).unwrap();
    let via_merge = merge(vec![parse_partial(toml, ProfileRole::Tenant).unwrap()]).unwrap();
    assert_eq!(via_parse, via_merge);
}

// --- [bootstrap] section -----------------------------------------------
//
// The profile grows an optional `[bootstrap]` table declaring shell
// commands the `tenant bootstrap` verb runs as the tenant:
// `commands = ["<shell string>", ...]`. Same backward-compat posture as
// `[inbound]`: absent section / empty list deserialize to an empty Vec
// (nothing to run). Merge concatenates fragments-first (one more list
// beside ports); an empty/whitespace-only entry is an authoring mistake
// refused per-file at parse (mirrors `ports = []`); duplicates are NOT
// refused (concat-no-dedupe — idempotence makes run two a no-op).

fn toml_with_bootstrap_section(bootstrap_body: &str) -> String {
    format!(
        "schema_version = 1\n\
         \n\
         [allowlist.runtime]\n\
         hosts = []\n\
         \n\
         [allowlist.install]\n\
         hosts = []\n\
         \n\
         {bootstrap_body}"
    )
}

#[test]
fn parses_bootstrap_commands_in_declared_order() {
    let toml = toml_with_bootstrap_section(
        "[bootstrap]\ncommands = [\"command -v rg || brew install ripgrep\", \"echo done\"]\n",
    );
    let profile = parse(&toml).expect("must parse");
    assert_eq!(
        profile.bootstrap.commands,
        vec![
            "command -v rg || brew install ripgrep".to_string(),
            "echo done".to_string(),
        ]
    );
}

#[test]
fn absent_bootstrap_section_yields_empty_commands() {
    // Backward-compat: profiles written before the bootstrap axis shipped
    // have no `[bootstrap]` section. Parse must succeed and yield an empty
    // Vec — nothing to run.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let profile = parse(toml).expect("must parse without bootstrap section");
    assert!(
        profile.bootstrap.commands.is_empty(),
        "expected empty bootstrap commands, got: {:?}",
        profile.bootstrap.commands
    );
}

#[test]
fn empty_bootstrap_commands_list_yields_empty_commands() {
    let toml = toml_with_bootstrap_section("[bootstrap]\ncommands = []\n");
    let profile = parse(&toml).expect("must parse");
    assert!(
        profile.bootstrap.commands.is_empty(),
        "expected empty bootstrap commands, got: {:?}",
        profile.bootstrap.commands
    );
}

#[test]
fn default_profile_toml_parses_with_empty_bootstrap_commands() {
    // The scaffold's `[bootstrap]` example entries are commented, so it
    // parses to an empty command list — a `tenant bootstrap` against a
    // fresh tenant is a quiet no-op. Value-identity of the parsed default
    // is pinned by the default_profile_toml tests above.
    let profile = parse(&default_profile_toml()).expect("default toml must parse");
    assert!(
        profile.bootstrap.commands.is_empty(),
        "expected default profile to have empty bootstrap commands, got: {:?}",
        profile.bootstrap.commands
    );
}

#[test]
fn default_profile_toml_carries_commented_bootstrap_hint() {
    // Scaffold carries a `[bootstrap]` section with commented example
    // entries — discoverable when editing, but a fresh tenant's
    // `tenant bootstrap` stays a quiet no-op (empty commands, pinned
    // above).
    let toml = default_profile_toml();
    assert!(
        toml.contains("[bootstrap]"),
        "scaffold must carry the [bootstrap] section; got:\n{toml}"
    );
    assert!(
        toml.contains("tenant bootstrap"),
        "hint must name the verb that runs the commands; got:\n{toml}"
    );
}

#[test]
fn parse_refuses_empty_bootstrap_command() {
    // Same posture as `ports = []`: a no-op command in the list is an
    // authoring mistake. Refused at parse (per-file, in parse_partial);
    // the load path names which file, so the message stays generic.
    let toml = toml_with_bootstrap_section("[bootstrap]\ncommands = [\"echo ok\", \"\"]\n");
    let err = parse(&toml).expect_err("empty command string must refuse");
    assert!(
        err.message.contains("bootstrap") && err.message.contains("empty"),
        "message must name the bootstrap empty-command mistake: {}",
        err.message
    );
}

#[test]
fn parse_refuses_whitespace_only_bootstrap_command() {
    let toml = toml_with_bootstrap_section("[bootstrap]\ncommands = [\"   \\t \"]\n");
    let err = parse(&toml).expect_err("whitespace-only command string must refuse");
    assert!(
        err.message.contains("bootstrap") && err.message.contains("empty"),
        "message must name the bootstrap empty-command mistake: {}",
        err.message
    );
}

#[test]
fn parse_partial_bootstrap_legal_in_fragment() {
    // A fragment may carry `[bootstrap]` — fleet-shared bootstrap via
    // includes. The per-file empty-command refusal still applies.
    let frag = "[bootstrap]\ncommands = [\"echo frag\"]\n[allowlist.runtime]\nhosts = []\n";
    let p = parse_partial(frag, ProfileRole::Fragment).expect("bootstrap in fragment must parse");
    assert_eq!(p.bootstrap.commands, vec!["echo frag".to_string()]);
}

#[test]
fn merge_unions_bootstrap_commands_fragments_first() {
    let frag = parse_partial(
        "[bootstrap]\ncommands = [\"frag-cmd\"]\n[allowlist.runtime]\nhosts = []\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n\
         [allowlist.runtime]\n\
         hosts = []\n\
         [allowlist.install]\n\
         hosts = []\n\
         [bootstrap]\n\
         commands = [\"prof-cmd\"]\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("must merge");
    assert_eq!(
        merged.bootstrap.commands,
        vec!["frag-cmd".to_string(), "prof-cmd".to_string()]
    );
}

#[test]
fn merge_does_not_dedupe_repeated_bootstrap_command() {
    // Concat-no-dedupe doctrine: a command in both a fragment and the
    // profile renders twice. Idempotence makes the second run a no-op.
    let frag = parse_partial(
        "[bootstrap]\ncommands = [\"echo same\"]\n[allowlist.runtime]\nhosts = []\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let prof = parse_partial(
        "schema_version = 1\n\
         [allowlist.install]\n\
         hosts = []\n\
         [bootstrap]\n\
         commands = [\"echo same\"]\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![frag, prof]).expect("must merge");
    assert_eq!(
        merged.bootstrap.commands,
        vec!["echo same".to_string(), "echo same".to_string()]
    );
}
