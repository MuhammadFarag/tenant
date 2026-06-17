//! E2E tests for the `tenant help <topic>` custom subcommand. Distinct
//! from clap's built-in `--help`: this verb dispatches through Reporter
//! to render a long-form topic body to stdout. The only topic today is
//! `profile`; new topics ship with a per-topic body test here.

mod adapters;
mod common;

use adapters::*;
use common::*;

#[test]
fn help_profile_exits_zero_and_renders_to_stdout() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["help", "profile"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert!(!stdout.is_empty(), "stdout should carry the topic body");
}

#[test]
fn help_profile_body_covers_load_bearing_concepts() {
    // The profile body must call out: the file location, the schema
    // anchor (`schema_version`), the two allowlist tiers, the
    // [[shares]] block + `$HOME` rule, the `[inbound]` ports section +
    // its honest-scope caveats, the `[provision]` non-goal, and the
    // `tenant reload <name>` apply step. Pin by substring rather than
    // byte-exact — the body's prose is allowed to shift; the concepts
    // are not.
    let (_code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["help", "profile"]);
    let needles = [
        "~/.config/tenant/profiles/<name>.toml",
        "schema_version",
        "[allowlist.runtime]",
        "[allowlist.install]",
        "[[shares]]",
        "host_path",
        "mode",
        "tenant_path",
        "$HOME",
        "ro",
        "rw",
        "[inbound]",
        "ports",
        // Honest-scope caveats: surface-reduction (not host-vs-peer),
        // intra-tenant cost, UDP unfiltered.
        "surface-reduction",
        "peer tenants",
        "OWN undeclared",
        "UDP",
        "[provision]",
        "git clone",
        "tenant reload",
    ];
    for needle in needles {
        assert!(
            stdout.contains(needle),
            "help profile body missing {needle:?}: {stdout}"
        );
    }
}

#[test]
fn help_with_unknown_topic_is_clap_parse_error() {
    // clap's ValueEnum rejects unknown topics at parse — exits 2 with
    // an error frame on stderr (clap's standard exit code for bad
    // arg/enum values). We don't need to render anything.
    let (code, _stdout, stderr) = run_with(StubUserDirectory::default(), &["help", "nonsense"]);
    assert_eq!(
        code, 2,
        "unknown topic should fail parse; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("nonsense"),
        "parse error should name the bad topic: {stderr}"
    );
}

#[test]
fn help_with_no_topic_lists_available_topics() {
    // Bare `tenant help` is the natural muscle-memory invocation; rather
    // than erroring out it renders an index of available topics so the
    // operator can discover what to ask for. Exit 0, stdout-only.
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["help"]);
    assert_eq!(code, 0, "bare `help` should succeed; stderr={stderr:?}");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    for needle in ["Available topics", "profile", "tenant help <topic>"] {
        assert!(
            stdout.contains(needle),
            "help index missing {needle:?}: {stdout}"
        );
    }
}

#[test]
fn help_profile_does_not_touch_substrate() {
    // help is a meta verb — no HostUserDirectory probes, no HostMachine ops.
    // `run_with` wires NeverHostMachine (panicking impl) so a successful
    // exit through this path proves no substrate call escaped.
    let (code, _stdout, _stderr) = run_with(StubUserDirectory::default(), &["help", "profile"]);
    assert_eq!(code, 0);
}
