//! Unit tests: `profile` parse/merge is a combinatorial pure-function state space.

use std::path::PathBuf;

use tenant::profile::{
    Allowlist, Bootstrap, HostEntry, Inbound, InboundPosture, PartialProfile, Profile, ProfileRole,
    Share, ShareMode, Tier, default_profile_toml, expand_tenant_path, merge, parse, parse_partial,
};

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
            inbound: Inbound::default(),
            bootstrap: Bootstrap { commands: vec![] },
        }
    );
}

#[test]
fn parse_populated_runtime_hosts_preserves_input_order() {
    // Hand-rolled TOML (not serde) so this pins the wire format the operator edits.
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
    // Refused at merge (completeness), not at parse_partial.
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

// --- per-host egress ports ---

#[test]
fn bare_host_string_resolves_to_port_443() {
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
    // serde's untagged-enum message is blunt: pin only that it errors.
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [{ ports = [443] }]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    parse(toml).expect_err("table entry missing host must be refused");
}

// --- [[shares]] table-array ---

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

// --- expand_tenant_path ---

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
    assert_eq!(
        expand_tenant_path("dev", "/opt/shared"),
        PathBuf::from("/opt/shared")
    );
}

#[test]
fn expand_tenant_path_does_not_expand_mid_string_home() {
    // Parse refuses mid-string `$HOME`; this pins expansion if one slips past anyway.
    assert_eq!(
        expand_tenant_path("dev", "/etc/$HOME/foo"),
        PathBuf::from("/etc/$HOME/foo")
    );
}

// --- $HOME prefix-only validation ---

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

// --- [inbound] section ---

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
    let profile = parse(&default_profile_toml()).expect("default toml must parse");
    assert!(
        profile.inbound.ports.is_empty(),
        "expected default profile to have empty inbound ports, got: {:?}",
        profile.inbound.ports
    );
}

#[test]
fn default_profile_toml_carries_commented_include_hint() {
    // Must stay commented: an active include fails every `tenant create` (no includes/base.toml yet).
    let toml = default_profile_toml();
    assert!(
        toml.contains("# include = [\"base\"]"),
        "scaffold must carry the commented include hint; got:\n{toml}"
    );
    assert!(
        toml.contains("includes/"),
        "hint must name the includes/ subdirectory; got:\n{toml}"
    );
    let partial = parse_partial(&toml, ProfileRole::Tenant).expect("default must parse");
    assert!(
        partial.include.is_empty(),
        "the include hint must stay commented (no active include); got {:?}",
        partial.include
    );
}

// --- include fragments: PartialProfile / parse_partial / merge ---

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
    let frag = "[allowlist.runtime]\nhosts = [\"api.anthropic.com\"]\n";
    let p = parse_partial(frag, ProfileRole::Fragment).expect("partial fragment must parse");
    assert_eq!(p.schema_version, None);
    assert!(p.allowlist.runtime.is_some());
    assert!(p.allowlist.install.is_none());
}

#[test]
fn parse_partial_empty_fragment_is_legal() {
    let p = parse_partial("", ProfileRole::Fragment).expect("empty fragment must parse");
    assert_eq!(p, PartialProfile::default());
}

#[test]
fn parse_partial_fragment_declaring_include_is_refused() {
    // Depth one: no nesting, so no cycle detection.
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
    // Mirrors validate_name's MAX_NAME_LEN = 31.
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
    let frag = "schema_version = 2\n";
    let err = parse_partial(frag, ProfileRole::Fragment).expect_err("schema 2 must refuse");
    assert_eq!(
        err.message,
        "schema_version 2 not understood (this tenant supports 1)"
    );
}

#[test]
fn parse_partial_runs_per_file_ports_and_home_validators() {
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
    assert_eq!(
        err.message,
        "two shares map to the same tenant_path \"$HOME/src\"; drop the include or \
         inline the share you want"
    );
}

#[test]
fn parse_single_file_duplicate_tenant_path_stays_value_identical() {
    // The collision refusal applies only across parts; a single file must not acquire it.
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
    let toml = "schema_version = 1\n\
                [allowlist.runtime]\n\
                hosts = [\"a\"]\n\
                [allowlist.install]\n\
                hosts = [\"b\"]\n";
    let via_parse = parse(toml).unwrap();
    let via_merge = merge(vec![parse_partial(toml, ProfileRole::Tenant).unwrap()]).unwrap();
    assert_eq!(via_parse, via_merge);
}

// --- [bootstrap] section ---

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
    let profile = parse(&default_profile_toml()).expect("default toml must parse");
    assert!(
        profile.bootstrap.commands.is_empty(),
        "expected default profile to have empty bootstrap commands, got: {:?}",
        profile.bootstrap.commands
    );
}

#[test]
fn default_profile_toml_carries_commented_bootstrap_hint() {
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
    // The load path names the file, so the message stays generic.
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

#[test]
fn merge_posture_is_permissive_when_any_part_declares_it() {
    let fragment = parse_partial(
        "[inbound]\nposture = \"permissive\"\n",
        ProfileRole::Fragment,
    )
    .unwrap();
    let profile = parse_partial(
        "schema_version = 1\n[allowlist.runtime]\nhosts = []\n[allowlist.install]\nhosts = []\n",
        ProfileRole::Tenant,
    )
    .unwrap();
    let merged = merge(vec![fragment, profile]).unwrap();
    assert_eq!(merged.inbound.posture, InboundPosture::Permissive);
}

#[test]
fn unknown_posture_value_rejected() {
    let toml = "schema_version = 1\n[allowlist.runtime]\nhosts = []\n[allowlist.install]\n\
                hosts = []\n[inbound]\nposture = \"open\"\n";
    assert!(parse(toml).is_err());
}
