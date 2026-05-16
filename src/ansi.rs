//! Internal ANSI escape-sequence wrapper for tenant's operator-facing
//! output.
//!
//! Three responsibilities:
//!   - color wrappers (`red`/`green`/`yellow`/`cyan`/`bold`/`dim`) that
//!     emit `\x1b[<code>m...\x1b[0m`,
//!   - a section-rule renderer (`rule`),
//!   - a box-panel renderer (`panel`) using rounded box-drawing chars.
//!
//! Gating: `should_color(Stream)` probes the named stream's terminal
//! state at runtime. Production composition (main.rs) computes this
//! once at startup and threads the booleans through `tenant::run` →
//! `Reporter::new`. Tests pass `false` so escape sequences don't leak
//! into byte-form fixtures.

use std::io::IsTerminal;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Per-stream color decision threaded from the composition root into
/// `Reporter`. Both off by default — tests' `Vec<u8>`-backed writers
/// aren't terminals, so byte-form fixtures stay clean without per-test
/// wiring. `main.rs` flips the bits at startup via `should_color`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Colors {
    pub stdout: bool,
    pub stderr: bool,
}

impl Colors {
    pub fn detect() -> Self {
        Self {
            stdout: should_color(Stream::Stdout),
            stderr: should_color(Stream::Stderr),
        }
    }
}

/// True when the named stream is connected to a terminal. Production
/// callers (main.rs) wrap this; tests don't go through it because their
/// `Vec<u8>`-backed writers aren't terminals anyway.
pub fn should_color(stream: Stream) -> bool {
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
}

fn wrap(s: &str, code: &str) -> String {
    format!("\x1b[{code}m{s}\x1b[0m")
}

pub fn red(s: &str) -> String {
    wrap(s, "31")
}

pub fn green(s: &str) -> String {
    wrap(s, "32")
}

pub fn yellow(s: &str) -> String {
    wrap(s, "33")
}

pub fn cyan(s: &str) -> String {
    wrap(s, "36")
}

pub fn bold(s: &str) -> String {
    wrap(s, "1")
}

pub fn dim(s: &str) -> String {
    wrap(s, "2")
}

/// `─── <title> ────────...` padded with `─` to `width` chars. If the
/// title is longer than the width, no padding; the title prints in full.
pub fn rule(title: &str, width: usize) -> String {
    let prefix = "─── ";
    let suffix_lead = " ";
    let core_chars = prefix.chars().count() + title.chars().count() + suffix_lead.chars().count();
    if core_chars >= width {
        return format!("{prefix}{title}{suffix_lead}");
    }
    let pad = width - core_chars;
    let dashes: String = "─".repeat(pad);
    format!("{prefix}{title}{suffix_lead}{dashes}")
}

/// Rounded-corner box around a multi-line body, with the title baked
/// into the top border:
///
/// ```text
/// ╭─ TITLE ──────────╮
/// │ body line 1      │
/// │ body line 2      │
/// ╰──────────────────╯
/// ```
///
/// `width` is the total character width including the corners. Body
/// lines longer than the available inner width print verbatim (overflow
/// rather than wrap) — tenant's panel content is short structured text,
/// not prose.
pub fn panel(title: &str, body: &str, width: usize) -> String {
    let width = width.max(8);
    // Top: ╭─ TITLE ─...─╮
    let title_segment = format!("─ {title} ");
    let title_chars = title_segment.chars().count();
    let inner_top = width - 2;
    let top_dashes = if title_chars >= inner_top {
        String::new()
    } else {
        "─".repeat(inner_top - title_chars)
    };
    let top = format!("╭{title_segment}{top_dashes}╮");

    // Body: │ <line padded to inner width - 2> │
    let inner = width - 4; // account for "│ " and " │"
    let mut out = String::new();
    out.push_str(&top);
    out.push('\n');
    for line in body.lines() {
        let line_chars = line.chars().count();
        let padding = if line_chars >= inner {
            String::new()
        } else {
            " ".repeat(inner - line_chars)
        };
        out.push_str(&format!("│ {line}{padding} │\n"));
    }
    // Bottom: ╰─...─╯
    let bottom_dashes = "─".repeat(width - 2);
    out.push_str(&format!("╰{bottom_dashes}╯"));
    out
}
