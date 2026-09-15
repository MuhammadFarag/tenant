//! Unit tests: `ansi` is a pure helper library with a combinatorial state space.

use tenant::ansi;

// ---------- color wrappers ----------

#[test]
fn red_wraps_with_red_esc_and_reset() {
    assert_eq!(ansi::red("x"), "\x1b[31mx\x1b[0m");
}

#[test]
fn green_wraps_with_green_esc_and_reset() {
    assert_eq!(ansi::green("x"), "\x1b[32mx\x1b[0m");
}

#[test]
fn yellow_wraps_with_yellow_esc_and_reset() {
    assert_eq!(ansi::yellow("x"), "\x1b[33mx\x1b[0m");
}

#[test]
fn cyan_wraps_with_cyan_esc_and_reset() {
    assert_eq!(ansi::cyan("x"), "\x1b[36mx\x1b[0m");
}

#[test]
fn bold_wraps_with_bold_esc_and_reset() {
    assert_eq!(ansi::bold("x"), "\x1b[1mx\x1b[0m");
}

#[test]
fn dim_wraps_with_dim_esc_and_reset() {
    assert_eq!(ansi::dim("x"), "\x1b[2mx\x1b[0m");
}

#[test]
fn empty_input_still_yields_esc_pair() {
    assert_eq!(ansi::red(""), "\x1b[31m\x1b[0m");
}

// ---------- rule ----------

#[test]
fn rule_renders_title_with_three_leading_dashes_and_pad_to_width() {
    let out = ansi::rule("Creating tenant 'devtest'", 80);
    assert!(out.starts_with("─── Creating tenant 'devtest' ───"));
    let chars: usize = out.chars().count();
    assert_eq!(chars, 80, "rule should pad to width 80, got {chars}");
}

#[test]
fn rule_with_short_width_still_renders_full_title() {
    let out = ansi::rule("Creating tenant 'devtest'", 10);
    assert!(out.contains("Creating tenant 'devtest'"));
}

// ---------- panel ----------

#[test]
fn panel_renders_rounded_corners_and_pipe_borders() {
    let out = ansi::panel("ERROR", "first line\nsecond line", 40);
    assert!(
        out.starts_with("╭"),
        "panel must start with rounded top-left ╭, got: {out}",
    );
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].contains("ERROR"), "first line: {}", lines[0]);
    let body_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with("│")).collect();
    assert_eq!(
        body_lines.len(),
        2,
        "expected 2 body lines, got {body_lines:?}"
    );
    let last = lines.last().expect("panel must have at least one line");
    assert!(
        last.starts_with("╰"),
        "panel must end with rounded bottom-left ╰, got: {last}",
    );
}

#[test]
fn panel_width_clamps_top_border_to_width() {
    let out = ansi::panel("X", "y", 30);
    let first_line_chars = out.lines().next().unwrap().chars().count();
    assert_eq!(
        first_line_chars, 30,
        "top border should match the width arg in char-count",
    );
}
