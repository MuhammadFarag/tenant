//! Unit tests for `doctor::has_group_acl_entry`: combinatorial over `ls -lde` ACL listings.

use tenant::doctor::has_group_acl_entry;

#[test]
fn detects_entry_with_canonical_macos_storage_bits() {
    // macOS rewrites stored bit names, so only the `group:<g> allow` prefix is matched.
    let listing = "drwxr-xr-x+ 5 op staff 160 May  1 12:34 /tmp/share\n\
                   \u{0020}0: group:dev-tenant-share allow list,add_file,search,delete,add_subdirectory\n";
    assert!(has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn detects_entry_with_pre_canonicalized_bits() {
    let listing = " 0: group:dev-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\n";
    assert!(has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn returns_false_when_no_acl_entries_present() {
    let listing = "drwxr-xr-x 5 op staff 160 May  1 12:34 /tmp/share\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn returns_false_when_only_other_group_present() {
    let listing = " 0: group:alpha-tenant-share allow list,add_file,search\n";
    assert!(!has_group_acl_entry(listing, "beta-tenant-share"));
    assert!(has_group_acl_entry(listing, "alpha-tenant-share"));
}

#[test]
fn handles_multiple_acl_entries_finds_target() {
    let listing = " 0: group:alpha-tenant-share allow list,add_file,search\n\
                   \u{0020}1: group:beta-tenant-share allow read,write,execute\n";
    assert!(has_group_acl_entry(listing, "alpha-tenant-share"));
    assert!(has_group_acl_entry(listing, "beta-tenant-share"));
    assert!(!has_group_acl_entry(listing, "gamma-tenant-share"));
}

#[test]
fn returns_false_on_prefix_collision() {
    let listing = " 0: group:dev allow read,write\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn ignores_deny_entries() {
    let listing = " 0: group:dev-tenant-share deny write\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn handles_leading_whitespace() {
    let listing = "    0: group:dev-tenant-share allow list,add_file,search\n";
    assert!(has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn ignores_commented_lines() {
    let listing = "# group:dev-tenant-share allow list,add_file,search\n";
    assert!(!has_group_acl_entry(listing, "dev-tenant-share"));
}

#[test]
fn returns_false_on_empty_listing() {
    assert!(!has_group_acl_entry("", "dev-tenant-share"));
}
