// Combinatorial coverage on `doctor::has_group_acl_entry`. The
// parser's call site is inside the writer's per-share drift loop
// and would otherwise need many overlapping E2E tests to exercise
// the shapes ACL listings take in practice. Same justification as
// `tests/env_policy_parse.rs` / `tests/pam_parse.rs`: per-shape
// unit testing on a pure function whose state space is combinatorial.

use tenant::doctor::has_group_acl_entry;

#[test]
fn detects_entry_with_canonical_macos_storage_bits() {
    // macOS canonicalizes the bit names on storage; the operator
    // wrote `chmod +a "group:dev-tenant-share allow read,write,..."`
    // and `ls -lde` reports the stored canonical form. The match must
    // succeed regardless of bit-list shape — `has_group_acl_entry`
    // looks for the `group:<g> allow` prefix only.
    let listing = "drwxr-xr-x+ 5 op staff 160 May  1 12:34 /tmp/share\n\
                   \u{0020}0: group:dev-tenant-share allow list,add_file,search,delete,add_subdirectory\n";
    assert!(has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn detects_entry_with_pre_canonicalized_bits() {
    // The `AclOp::Grant` substrate writes the
    // `read,write,execute,...` form. If `ls -lde` is queried before
    // macOS has canonicalized (or never canonicalizes — depends on
    // macOS version), the line stores the operator's input shape.
    // Match must succeed on this shape too.
    let listing = " 0: group:dev-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\n";
    assert!(has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn returns_false_when_no_acl_entries_present() {
    // The simplest drift signal: `ls -lde` reports only POSIX bits,
    // no `+` after permissions, no `N:` numbered ACL block. Operator
    // ran `chmod -a` or `cp -R` clobbered the entries.
    let listing = "drwxr-xr-x 5 op staff 160 May  1 12:34 /tmp/share\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn returns_false_when_only_other_group_present() {
    // Multi-tenant host: `/tmp/shared` has tenant-A's group ACL but
    // not tenant-B's. Querying for tenant-B's group must report
    // missing.
    let listing = " 0: group:alpha-tenant-share allow list,add_file,search\n";
    assert!(!has_group_acl_entry(listing, "beta-tenant-share"));
    assert!(has_group_acl_entry(listing, "alpha-tenant-share"));
}

#[test]
fn handles_multiple_acl_entries_finds_target() {
    // Multi-tenant share: same host_path carries entries for both
    // tenant-A and tenant-B (each independently declared in their
    // own profile). Each query finds its own group.
    let listing = " 0: group:alpha-tenant-share allow list,add_file,search\n\
                   \u{0020}1: group:beta-tenant-share allow read,write,execute\n";
    assert!(has_group_acl_entry(listing, "alpha-tenant-share"));
    assert!(has_group_acl_entry(listing, "beta-tenant-share"));
    assert!(!has_group_acl_entry(listing, "gamma-tenant-share"));
}

#[test]
fn returns_false_on_prefix_collision() {
    // `group:dev allow` MUST NOT match a query for `dev-tenant-share`.
    // The word-boundary discipline in `has_group_acl_entry` uses the
    // ` allow` suffix to delimit the group name on the right; the
    // collision case checks that this works.
    let listing = " 0: group:dev allow read,write\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn ignores_deny_entries() {
    // ACL entries can be `allow` or `deny`. Doctor's AclDrift fires
    // on absence of an `allow` entry; a `deny` entry for the same
    // group is NOT the expected match (it would block tenant access
    // — different operator-visible problem).
    let listing = " 0: group:dev-tenant-share deny write\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn handles_leading_whitespace() {
    // `ls -lde` indents the numbered ACL block with leading spaces.
    // The parser trims left-whitespace before checking the comment
    // gate; matching is substring-based so leading whitespace passes
    // through transparently for the actual content.
    let listing = "    0: group:dev-tenant-share allow list,add_file,search\n";
    assert!(has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn ignores_commented_lines() {
    // Defensive: `ls -lde` doesn't emit comments, but the parser
    // skips `#`-prefixed lines (consistent with env_policy / pam
    // parsers) so hand-crafted test fixtures or future tool output
    // changes don't false-positive.
    let listing = "# group:dev-tenant-share allow list,add_file,search\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn returns_false_on_empty_listing() {
    assert!(!has_group_acl_entry("", "dev-tenant-share"));
}
