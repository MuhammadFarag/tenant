use std::io::Write;

use crate::messages::Message;

pub(crate) struct Reporter<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    verbose: bool,
    dry_run: bool,
}

impl<'a> Reporter<'a> {
    pub fn new(
        stdout: &'a mut dyn Write,
        stderr: &'a mut dyn Write,
        verbose: bool,
        dry_run: bool,
    ) -> Self {
        Self {
            stdout,
            stderr,
            verbose,
            dry_run,
        }
    }

    pub fn emit(&mut self, msg: Message) {
        Self::emit_to(self.stdout, &msg, self.verbose, self.dry_run);
    }

    pub fn emit_err(&mut self, msg: Message) {
        Self::emit_to(self.stderr, &msg, self.verbose, self.dry_run);
    }

    fn emit_to(target: &mut dyn Write, msg: &Message, verbose: bool, dry_run: bool) {
        // In dry-run mode, prefer dry_run_summary; fall back to summary when the
        // message has no mode-specific override (errors, conflicts).
        let summary = if dry_run {
            msg.dry_run_summary.as_ref().or(msg.summary.as_ref())
        } else {
            msg.summary.as_ref()
        };
        if let Some(s) = summary {
            let _ = writeln!(target, "{s}");
        }
        if verbose && let Some(detail) = &msg.detail {
            let _ = writeln!(target, "{detail}");
        }
    }
}
