use std::io::Write;

use crate::messages::Message;

pub(crate) struct Reporter<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    verbose: bool,
}

impl<'a> Reporter<'a> {
    pub fn new(stdout: &'a mut dyn Write, stderr: &'a mut dyn Write, verbose: bool) -> Self {
        Self {
            stdout,
            stderr,
            verbose,
        }
    }

    pub fn write(&mut self, msg: Message) {
        Self::emit(self.stdout, &msg, self.verbose);
    }

    pub fn write_err(&mut self, msg: Message) {
        Self::emit(self.stderr, &msg, self.verbose);
    }

    fn emit(target: &mut dyn Write, msg: &Message, verbose: bool) {
        if let Some(summary) = &msg.summary {
            let _ = writeln!(target, "{summary}");
        }
        if verbose && let Some(detail) = &msg.detail {
            let _ = writeln!(target, "{detail}");
        }
    }
}
