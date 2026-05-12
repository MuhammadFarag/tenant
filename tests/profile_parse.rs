//! Combinatorial coverage on `profile::parse`. Tests the free-function
//! parser directly because no verb wires the read+parse path until 2.4
//! (create-side firewall step), and the matrix here is parser-state-shaped
//! (schema version × structural completeness × TOML well-formedness) which
//! is awkward to drive through the CLI surface. Same in-tree precedent
//! and justification as `tests/macos_executor.rs`'s per-variant pins on
//! `MacosExecutor::describe_*`.

use tenant::profile::{Allowlist, Profile, Tier, default_profile_toml, parse};

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
