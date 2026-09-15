//! `tenant help <topic>`: the custom topic verb, not clap's `--help`.

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
    // Substring pins: the prose may shift, the concepts may not.
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
        "surface-reduction",
        "peer tenants",
        "OWN undeclared",
        "UDP",
        "[bootstrap]",
        "tenant bootstrap",
        "/bin/sh -c",
        "does not manage or template",
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
    // `run_with` wires NeverHostMachine, so a clean exit proves no substrate call.
    let (code, _stdout, _stderr) = run_with(StubUserDirectory::default(), &["help", "profile"]);
    assert_eq!(code, 0);
}
