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

    /// Emit on stderr unconditionally. Reporter picks the right summary
    /// for the current mode/verbosity.
    pub fn emit_err(&mut self, msg: Message) {
        Self::emit_to(self.stderr, &msg, self.verbose, self.dry_run);
    }

    /// Emit on stdout unconditionally — used for messages whose framing
    /// is the same in real and dry-run modes (e.g. the convergent-noop
    /// "tenant 'X' does not exist; nothing to do." line).
    pub fn emit(&mut self, msg: Message) {
        Self::emit_to(self.stdout, &msg, self.verbose, self.dry_run);
    }

    /// Emit only when in real mode (silent in dry-run). Use for messages
    /// that would be a lie in dry-run, e.g. post-exec confirmations.
    pub fn emit_real_only(&mut self, msg: Message) {
        if !self.dry_run {
            Self::emit_to(self.stdout, &msg, self.verbose, self.dry_run);
        }
    }

    /// Emit only when in dry-run mode (silent in real mode). Use for
    /// "Would …" framing that's only meaningful when nothing happens.
    pub fn emit_dry_only(&mut self, msg: Message) {
        if self.dry_run {
            Self::emit_to(self.stdout, &msg, self.verbose, self.dry_run);
        }
    }

    fn emit_to(target: &mut dyn Write, msg: &Message, verbose: bool, dry_run: bool) {
        // Summary selection precedence:
        //   dry-run mode  → dry_run_summary, falling back to summary
        //   real+verbose  → summary_verbose, falling back to summary
        //   real+standard → summary
        let summary = if dry_run {
            msg.dry_run_summary.as_ref().or(msg.summary.as_ref())
        } else if verbose {
            msg.summary_verbose.as_ref().or(msg.summary.as_ref())
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
