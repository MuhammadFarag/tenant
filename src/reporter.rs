use std::io::Write;

use crate::messages::Message;

pub(crate) struct Reporter<'a> {
    stdout: &'a mut dyn Write,
    verbose: bool,
}

impl<'a> Reporter<'a> {
    pub fn new(stdout: &'a mut dyn Write, verbose: bool) -> Self {
        Self { stdout, verbose }
    }

    pub fn write(&mut self, msg: Message) {
        if let Some(summary) = msg.summary {
            let _ = writeln!(self.stdout, "{summary}");
        }
        if self.verbose
            && let Some(detail) = msg.detail
        {
            let _ = writeln!(self.stdout, "{detail}");
        }
    }
}
