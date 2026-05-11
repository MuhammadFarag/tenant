//! Generic CLI execution interface — the substitution boundary for tests.
//!
//! Domain writers (e.g. `accounts::MacosWriter`) build argv and hand it to
//! an `Executor`. Production wires `SystemExecutor` (uses `Command::output`,
//! capturing stdout/stderr so tool noise is suppressed on success and
//! surfaced via `ExecError::NonZero` on failure). Sudo's password prompt
//! still works in this mode because sudo writes to `/dev/tty` directly,
//! not to the subprocess's stderr. Tests wire `StubExecutor`, which records
//! each invocation and returns a configured outcome.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::io;
use std::process::Command;

#[derive(Debug)]
pub enum ExecError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::Spawn(e) => write!(f, "failed to spawn process: {e}"),
            ExecError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "process exited with code {code}")
                } else {
                    write!(f, "process exited with code {code}: {trimmed}")
                }
            }
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
        // .output() pipes stdout/stderr so we can suppress sysadminctl's
        // verbose chatter on success. Sudo's password prompt still reaches
        // the user via /dev/tty (sudo doesn't use the subprocess's stderr
        // for the prompt by default).
        let output = Command::new(program)
            .args(rest)
            .output()
            .map_err(ExecError::Spawn)?;
        if !output.status.success() {
            return Err(ExecError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
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
/// outcome. Use `StubExecutor::new()` for a success-by-default stub,
/// `StubExecutor::failing(code)` for a non-zero exit with empty stderr,
/// or `StubExecutor::failing_with(code, stderr)` to simulate a tool that
/// printed something to stderr before exiting.
///
/// For multi-call paths where one specific argv should fail (e.g. the
/// destroy verb's dscl-read probe returning eDSRecordNotFound while
/// sysadminctl succeeds), chain `.with_response_to(prefix, code)` —
/// any call whose argv starts with `prefix` returns `NonZero { code, .. }`
/// instead of the global default. First registered match wins.
#[derive(Default)]
pub struct StubExecutor {
    calls: RefCell<Vec<Vec<String>>>,
    fail_code: Cell<Option<i32>>,
    fail_stderr: RefCell<String>,
    overrides: RefCell<Vec<(Vec<String>, i32, String)>>,
}

impl StubExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn failing(code: i32) -> Self {
        Self::failing_with(code, "")
    }

    pub fn failing_with(code: i32, stderr: &str) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            fail_code: Cell::new(Some(code)),
            fail_stderr: RefCell::new(stderr.to_string()),
            overrides: RefCell::new(Vec::new()),
        }
    }

    /// Register a per-argv-prefix override. When a `run` call's argv starts
    /// with `prefix`, the executor returns `NonZero { code, stderr: "" }`
    /// instead of the global default. Multiple overrides may be registered;
    /// the first match in registration order wins. Use `with_response_to_stderr`
    /// when the test needs to assert against captured stderr.
    pub fn with_response_to(self, prefix: &[&str], code: i32) -> Self {
        self.with_response_to_stderr(prefix, code, "")
    }

    pub fn with_response_to_stderr(self, prefix: &[&str], code: i32, stderr: &str) -> Self {
        self.overrides.borrow_mut().push((
            prefix.iter().map(|s| (*s).to_string()).collect(),
            code,
            stderr.to_string(),
        ));
        self
    }

    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }
}

impl Executor for StubExecutor {
    fn run(&self, argv: &[String]) -> Result<(), ExecError> {
        self.calls.borrow_mut().push(argv.to_vec());
        // Per-argv overrides take precedence over the global fail_code so a
        // test can say "everything succeeds except the dscl-read probe".
        for (prefix, code, stderr) in self.overrides.borrow().iter() {
            if argv.starts_with(prefix) {
                return Err(ExecError::NonZero {
                    code: *code,
                    stderr: stderr.clone(),
                });
            }
        }
        match self.fail_code.get() {
            None => Ok(()),
            Some(code) => Err(ExecError::NonZero {
                code,
                stderr: self.fail_stderr.borrow().clone(),
            }),
        }
    }
}
