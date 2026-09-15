//! Unit tests for `doctor::pf_rule_presence_check`: combinatorial over pfctl output shapes.

use tenant::doctor::{Finding, pf_rule_presence_check};

// --- Both rules present ---

#[test]
fn both_rules_present_no_findings() {
    let rules = "block return inet from any to any\n\
                 pass inet from 192.0.2.1 to <allowed> keep state\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert!(
        findings.is_empty(),
        "expected no findings; got {findings:?}"
    );
}

#[test]
fn rules_in_reversed_order_still_pass() {
    let rules = "pass inet from 192.0.2.1 to <allowed> keep state\n\
                 block return inet from any to any\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn leading_whitespace_tolerated() {
    let rules = "    block return inet from any to any\n\
                 \tpass inet from 192.0.2.1 to <allowed> keep state\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert!(
        findings.is_empty(),
        "leading whitespace must be tolerated; got {findings:?}"
    );
}

#[test]
fn multiple_pass_rules_one_block_is_fine() {
    let rules = "block return inet from any to any\n\
                 pass inet from 10.0.0.1 to <allowed>\n\
                 pass inet from 10.0.0.2 to <allowed>\n\
                 pass inet from 10.0.0.3 to <allowed>\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert!(findings.is_empty(), "got {findings:?}");
}

// --- One rule class missing ---

#[test]
fn missing_pass_emits_one_finding_naming_pass() {
    let rules = "block return inet from any to any\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert_eq!(findings.len(), 1, "got {findings:?}");
    match &findings[0] {
        Finding::PfRuleDrift { tenant, detail } => {
            assert_eq!(tenant, "dev");
            assert!(
                detail.contains("pass"),
                "detail should name the missing class; got {detail:?}"
            );
        }
        other => panic!("expected PfRuleDrift; got {other:?}"),
    }
}

#[test]
fn missing_block_emits_one_finding_naming_block() {
    let rules = "pass inet from 192.0.2.1 to <allowed> keep state\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert_eq!(findings.len(), 1, "got {findings:?}");
    match &findings[0] {
        Finding::PfRuleDrift { tenant, detail } => {
            assert_eq!(tenant, "dev");
            assert!(
                detail.contains("block"),
                "detail should name the missing class; got {detail:?}"
            );
        }
        other => panic!("expected PfRuleDrift; got {other:?}"),
    }
}

// --- Both rule classes missing ---

#[test]
fn empty_input_emits_two_findings_pass_then_block() {
    let findings = pf_rule_presence_check("", "dev");
    assert_eq!(findings.len(), 2);
    match (&findings[0], &findings[1]) {
        (Finding::PfRuleDrift { detail: d1, .. }, Finding::PfRuleDrift { detail: d2, .. }) => {
            assert!(d1.contains("pass"), "first detail names pass; got {d1:?}");
            assert!(
                d2.contains("block"),
                "second detail names block; got {d2:?}"
            );
        }
        other => panic!("expected two PfRuleDrift findings; got {other:?}"),
    }
}

#[test]
fn whitespace_only_input_emits_two_findings() {
    let findings = pf_rule_presence_check("   \n\t\n\n", "dev");
    assert_eq!(findings.len(), 2);
}

// --- Substring / comment / wrong prefix don't count ---

#[test]
fn commented_pass_rule_does_not_count() {
    let rules = "# pass-through note for future operator\n\
                 block return inet from any to any\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert_eq!(findings.len(), 1);
    match &findings[0] {
        Finding::PfRuleDrift { detail, .. } => {
            assert!(
                detail.contains("pass"),
                "commented line shouldn't count; got {detail:?}"
            );
        }
        other => panic!("expected PfRuleDrift; got {other:?}"),
    }
}

#[test]
fn substring_pass_in_other_word_does_not_count() {
    let rules = "block return inet from any to any\n\
                 # bypass logic for keepalives — see anchor file\n\
                 # passport-control IP ranges below\n";
    let findings = pf_rule_presence_check(rules, "dev");
    assert_eq!(
        findings.len(),
        1,
        "must still see missing-pass; got {findings:?}"
    );
}

#[test]
fn tenant_name_propagates_into_finding() {
    let findings = pf_rule_presence_check("", "staging");
    for f in &findings {
        match f {
            Finding::PfRuleDrift { tenant, .. } => assert_eq!(tenant, "staging"),
            other => panic!("expected PfRuleDrift; got {other:?}"),
        }
    }
}
