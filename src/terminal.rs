//! Operator's terminal-I/O capability. Threaded through every construct
//! that needs operator I/O — even those that only read one field. This
//! struct IS the access path; do not unpack its fields into separate
//! parameters or fields downstream.

use std::io::{BufRead, Write};

use crate::ansi::Colors;

pub struct Terminal<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub stdin: &'a mut dyn BufRead,
    pub stdin_is_tty: bool,
    pub colors: Colors,
}
