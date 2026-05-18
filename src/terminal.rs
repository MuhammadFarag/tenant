//! Operator's terminal-I/O capability. Threaded through every construct
//! that needs operator I/O — even those that only read one field. This
//! struct IS the access path; do not unpack its fields into separate
//! parameters or fields downstream.

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
    /// Construct a `Terminal` over OS stdio for the duration of `f`.
    /// The closure pattern is load-bearing: `Terminal`'s borrowed
    /// fields can't outlive the OS handles that back them.
    ///
    /// `StdinLock` implements `BufRead`; `Stdin` doesn't — hence the
    /// separate `stdin_handle.lock()`.
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
