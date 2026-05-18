use std::io::IsTerminal;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

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
/// rather than wrap).
pub fn panel(title: &str, body: &str, width: usize) -> String {
    let width = width.max(8);
    let title_segment = format!("─ {title} ");
    let title_chars = title_segment.chars().count();
    let inner_top = width - 2;
    let top_dashes = if title_chars >= inner_top {
        String::new()
    } else {
        "─".repeat(inner_top - title_chars)
    };
    let top = format!("╭{title_segment}{top_dashes}╮");

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
    let bottom_dashes = "─".repeat(width - 2);
    out.push_str(&format!("╰{bottom_dashes}╯"));
    out
}
