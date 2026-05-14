//! Combinatorial coverage on `profile::parse`. Tests the free-function
//! parser directly because no verb wires the read+parse path until 2.4
//! (create-side firewall step), and the matrix here is parser-state-shaped
//! (schema version × structural completeness × TOML well-formedness) which
//! is awkward to drive through the CLI surface. Same in-tree precedent
//! and justification as `tests/macos_executor.rs`'s per-variant pins on
//! `MacosExecutor::describe_*`.

use std::path::PathBuf;

use tenant::profile::{
    Allowlist, Profile, Share, ShareMode, Tier, default_profile_toml, expand_tenant_path, parse,
};

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
            "api.anthropic.com".to_string(),
            "github.com".to_string(),
            "crates.io".to_string(),
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
        vec!["registry.npmjs.org".to_string(), "pypi.org".to_string()]
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
    // serde's "missing field" frame; the dispatcher's Reporter call
    // wraps this in the path-naming frame so the operator gets full
    // context end-to-end.
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

// --- [[shares]] table-array (cycle 10) ---------------------------------
//
// The profile grows an optional table-array declaring per-tenant
// filesystem shares: `(host_path, mode, tenant_path)` triples. Mode is a
// string discriminator (`"ro"` / `"rw"`) — POSIX bit-string forms
// rejected because POSIX bit semantics differ for files vs directories.
// `tenant_path` is stored raw (template form with `$HOME` if used); the
// Writer expands at op-construction time. Backward-compat: missing
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
    // Q13 lock: profile-declared order, not alphabetical-by-host-path.
    // Same convention as `allowlist.runtime.hosts`. Operator-readable;
    // order doesn't affect correctness (idempotent substrate) — preserving
    // intent is the small win.
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
    // Q3 lock: `$HOME` is the only template variable; expansion happens
    // in the Writer when it resolves the share entry. The parser stores
    // the raw string so the type itself signals "this is a template, not
    // yet resolved" — a substrate call against a raw template would be
    // a type mistake at construction time.
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
    // Backward-compat: every profile written by `tenant create` before
    // cycle 10 has no `[[shares]]` section. Parse must succeed and yield
    // an empty Vec so cycle-9-era profiles keep working.
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
    // Q1 lock: only `"ro"` and `"rw"` accepted. POSIX bit-string forms
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

// --- expand_tenant_path (cycle 10) ------------------------------------
//
// Q3 lock: `$HOME` is the only template variable. The Writer expands it
// to `/Users/<tenant>` at op-construction time; the substrate sees
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

// --- $HOME prefix-only validation (cycle 10 round 1 review) -----------
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
