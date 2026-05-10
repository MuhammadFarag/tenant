//! Generic CLI execution interface — the substitution boundary for tests.
//!
//! Domain writers (e.g. `accounts::MacosWriter`) build argv and hand it to
//! an `Executor`. Production wires `SystemExecutor` (real `Command::status`
//! with inherited stdio so `sudo` can prompt). Tests wire `StubExecutor`,
//! which records each invocation and returns a configured outcome.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::io;
use std::process::Command;

#[derive(Debug)]
pub enum ExecError {
    Spawn(io::Error),
    NonZero(i32),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::Spawn(e) => write!(f, "failed to spawn process: {e}"),
            ExecError::NonZero(code) => write!(f, "process exited with code {code}"),
        }
    }
}

pub trait Executor {
    fn run(&self, argv: &[String]) -> Result<(), ExecError>;
}

pub struct SystemExecutor;

impl Executor for SystemExecutor {
    fn run(&self, argv: &[String]) -> Result<(), ExecError> {
        let (program, rest) = argv
            .split_first()
            .ok_or_else(|| ExecError::Spawn(io::Error::other("argv is empty")))?;
        // .status() inherits stdin/stdout/stderr — required so `sudo`'s
        // password prompt reaches the user's terminal and any tool stderr
        // is visible without us re-emitting it.
        let status = Command::new(program)
            .args(rest)
            .status()
            .map_err(ExecError::Spawn)?;
        if !status.success() {
            return Err(ExecError::NonZero(status.code().unwrap_or(-1)));
        }
        Ok(())
    }
}

/// Production no-op executor. Returns Ok without spawning anything; the
/// composition root swaps this in when `--dry-run` is set so that domain
/// writers don't need to know about the mode.
pub struct DryRunExecutor;

impl Executor for DryRunExecutor {
    fn run(&self, _argv: &[String]) -> Result<(), ExecError> {
        Ok(())
    }
}

/// Test double that records every invocation and returns a configured
/// outcome. Use `StubExecutor::new()` for a success-by-default stub or
/// `StubExecutor::failing(code)` to simulate a non-zero exit.
#[derive(Default)]
pub struct StubExecutor {
    calls: RefCell<Vec<Vec<String>>>,
    fail_code: Cell<Option<i32>>,
}

impl StubExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn failing(code: i32) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            fail_code: Cell::new(Some(code)),
        }
    }

    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }
}

impl Executor for StubExecutor {
    fn run(&self, argv: &[String]) -> Result<(), ExecError> {
        self.calls.borrow_mut().push(argv.to_vec());
        match self.fail_code.get() {
            None => Ok(()),
            Some(code) => Err(ExecError::NonZero(code)),
        }
    }
}
