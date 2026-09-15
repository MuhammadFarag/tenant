use std::io::{self, BufRead, IsTerminal, Write};

use crate::ansi::Colors;

pub struct Terminal<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub stdin: &'a mut dyn BufRead,
    pub stdin_is_tty: bool,
    pub colors: Colors,
}

impl Terminal<'_> {
    /// Closure-scoped: the borrowed fields can't outlive the OS handles.
    pub fn with_stdio<F, R>(f: F) -> R
    where
        F: FnOnce(Terminal<'_>) -> R,
    {
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        let stdin_handle = io::stdin();
        let stdin_is_tty = stdin_handle.is_terminal();
        let mut stdin = stdin_handle.lock();
        let colors = Colors::detect();
        let terminal = Terminal {
            stdout: &mut stdout,
            stderr: &mut stderr,
            stdin: &mut stdin,
            stdin_is_tty,
            colors,
        };
        f(terminal)
    }
}
