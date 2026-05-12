//! Combinatorial coverage on the `/etc/pf.conf` line-op free functions
//! in `firewall`: `ensure_anchor_ref`, `remove_anchor_ref`,
//! `is_anchor_referenced`. Each function has a matrix of input states
//! (both lines present, neither, partial, with-other-anchors) that
//! drives the idempotence + non-interference contracts. Same in-tree
//! precedent as `tests/macos_executor.rs` / `tests/firewall_render.rs`
//! / `tests/profile_parse.rs` — pure functions whose call sites land
//! in 2.4 with a verb consumer, so unit tests precede the CLI tests.

use tenant::firewall::{ensure_anchor_ref, is_anchor_referenced, remove_anchor_ref};

const ANCHOR_DEV: &str = "anchor \"tenant-dev\"";
const LOAD_DEV: &str = "load anchor \"tenant-dev\" from \"/etc/pf.anchors/tenant-dev\"";
const ANCHOR_OTHER: &str = "anchor \"tenant-other\"";
const LOAD_OTHER: &str = "load anchor \"tenant-other\" from \"/etc/pf.anchors/tenant-other\"";

#[test]
fn ensure_anchor_ref_adds_both_lines_to_empty_conf() {
    let result = ensure_anchor_ref("", "dev");
    assert_eq!(result, format!("{ANCHOR_DEV}\n{LOAD_DEV}\n"));
}

#[test]
fn ensure_anchor_ref_is_idempotent_when_both_present() {
    let initial = format!("{ANCHOR_DEV}\n{LOAD_DEV}\n");
    let result = ensure_anchor_ref(&initial, "dev");
    assert_eq!(result, initial, "must not modify when both lines present");
}

#[test]
fn ensure_anchor_ref_adds_only_missing_load_when_anchor_present() {
    let initial = format!("{ANCHOR_DEV}\n");
    let result = ensure_anchor_ref(&initial, "dev");
    assert_eq!(
        result,
        format!("{ANCHOR_DEV}\n{LOAD_DEV}\n"),
        "must append only the load line; existing anchor stays once"
    );
}

#[test]
fn ensure_anchor_ref_adds_only_missing_anchor_when_load_present() {
    let initial = format!("{LOAD_DEV}\n");
    let result = ensure_anchor_ref(&initial, "dev");
    assert_eq!(
        result,
        format!("{LOAD_DEV}\n{ANCHOR_DEV}\n"),
        "must append only the anchor line; existing load stays once"
    );
}

#[test]
fn ensure_anchor_ref_does_not_affect_unrelated_anchors() {
    // A host with a `tenant-other` already installed must not have its
    // lines touched when `dev` is ensured.
    let initial = format!("{ANCHOR_OTHER}\n{LOAD_OTHER}\n");
    let result = ensure_anchor_ref(&initial, "dev");
    assert_eq!(
        result,
        format!("{ANCHOR_OTHER}\n{LOAD_OTHER}\n{ANCHOR_DEV}\n{LOAD_DEV}\n"),
        "must append dev lines without touching other lines"
    );
}

#[test]
fn remove_anchor_ref_removes_both_lines() {
    let initial = format!("{ANCHOR_DEV}\n{LOAD_DEV}\n");
    let result = remove_anchor_ref(&initial, "dev");
    assert_eq!(result, "");
}

#[test]
fn remove_anchor_ref_is_idempotent_when_absent() {
    let initial = "# unrelated comment\nanchor \"tenant-other\"\n";
    let result = remove_anchor_ref(initial, "dev");
    assert_eq!(result, initial, "must not modify when target absent");
}

#[test]
fn remove_anchor_ref_preserves_unrelated_lines() {
    let initial = format!(
        "# header comment\n\
         {ANCHOR_OTHER}\n\
         {ANCHOR_DEV}\n\
         {LOAD_OTHER}\n\
         {LOAD_DEV}\n"
    );
    let result = remove_anchor_ref(&initial, "dev");
    assert_eq!(
        result,
        format!("# header comment\n{ANCHOR_OTHER}\n{LOAD_OTHER}\n"),
        "must remove dev lines while preserving other content order"
    );
}

#[test]
fn is_anchor_referenced_distinguishes_anchor_from_load_substring() {
    // The bare `anchor "tenant-dev"` text is a substring of the
    // `load anchor "tenant-dev" from ...` line. Substring-based checks
    // would falsely report the anchor line as present when only the
    // load line is there — but `pfctl -f` needs both to actually
    // install the rules. Line-level matching is the contract.
    let only_load = format!("{LOAD_DEV}\n");
    assert!(
        !is_anchor_referenced(&only_load, "dev"),
        "load line alone must NOT satisfy 'anchor referenced'"
    );

    let only_anchor = format!("{ANCHOR_DEV}\n");
    assert!(
        !is_anchor_referenced(&only_anchor, "dev"),
        "anchor line alone must NOT satisfy 'anchor referenced'"
    );

    let both = format!("{ANCHOR_DEV}\n{LOAD_DEV}\n");
    assert!(
        is_anchor_referenced(&both, "dev"),
        "both lines together must satisfy 'anchor referenced'"
    );
}
