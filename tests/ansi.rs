//! Combinatorial pin on `src/ansi.rs` color helpers + box renderers.
//! Justified as a unit-test file because the module is a pure function
//! library (no I/O) and its state space is combinatorial — same pattern
//! as `firewall_render.rs` and `doctor.rs`.

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
    // Edge case — wrap-empty must still emit the reset so a following
    // string isn't accidentally colored.
    assert_eq!(ansi::red(""), "\x1b[31m\x1b[0m");
}

// ---------- rule ----------

#[test]
fn rule_renders_title_with_three_leading_dashes_and_pad_to_width() {
    // ─── Creating tenant 'devtest' ────────...─── (padded to 80)
    let out = ansi::rule("Creating tenant 'devtest'", 80);
    assert!(out.starts_with("─── Creating tenant 'devtest' ───"));
    // Width in chars (not bytes — each `─` is 3 bytes in UTF-8).
    let chars: usize = out.chars().count();
    assert_eq!(chars, 80, "rule should pad to width 80, got {chars}");
}

#[test]
fn rule_with_short_width_still_renders_full_title() {
    // Width smaller than the title should still emit the full title;
    // no truncation. Trailing dashes vanish or become a single trailer.
    let out = ansi::rule("Creating tenant 'devtest'", 10);
    assert!(out.contains("Creating tenant 'devtest'"));
}

// ---------- panel ----------

#[test]
fn panel_renders_rounded_corners_and_pipe_borders() {
    let out = ansi::panel("ERROR", "first line\nsecond line", 40);
    // Top-left corner.
    assert!(
        out.starts_with("╭"),
        "panel must start with rounded top-left ╭, got: {out}",
    );
    // Title appears in first line.
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].contains("ERROR"), "first line: {}", lines[0]);
    // Body lines wrapped with │ ... │.
    let body_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with("│")).collect();
    assert_eq!(
        body_lines.len(),
        2,
        "expected 2 body lines, got {body_lines:?}"
    );
    // Last line is the bottom border with ╰.
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
