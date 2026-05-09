use std::collections::HashSet;
use std::io;
use std::process::Command;

use crate::executor::{ExecError, Executor};
use crate::messages;
use crate::reporter::Reporter;

pub trait Reader {
    fn used_uids(&self) -> Vec<u32>;
    fn has_user(&self, name: &str) -> bool;
    fn has_group(&self, name: &str) -> bool;
}

#[derive(Default)]
pub struct StubReader {
    pub uids: Vec<u32>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
}

impl Reader for StubReader {
    fn used_uids(&self) -> Vec<u32> {
        self.uids.clone()
    }

    fn has_user(&self, name: &str) -> bool {
        self.users.iter().any(|u| u == name)
    }

    fn has_group(&self, name: &str) -> bool {
        self.groups.iter().any(|g| g == name)
    }
}

const MAX_NAME_LEN: usize = 31;

#[derive(Debug)]
pub enum NameError {
    Empty,
    InvalidStart(char),
    InvalidCharacter(char),
    TooLong { len: usize, max: usize },
}

#[derive(Debug)]
pub enum ConflictError {
    UserExists,
    GroupExists,
    Both,
}

pub fn check_conflict(reader: &dyn Reader, name: &str) -> Result<(), ConflictError> {
    match (reader.has_user(name), reader.has_group(name)) {
        (false, false) => Ok(()),
        (true, false) => Err(ConflictError::UserExists),
        (false, true) => Err(ConflictError::GroupExists),
        (true, true) => Err(ConflictError::Both),
    }
}

/// Real `Reader` backed by `dscl`. Queries the local Open Directory node
/// once at construction and serves all subsequent lookups from memory.
pub struct MacosReader {
    users: HashSet<String>,
    groups: HashSet<String>,
    uids: Vec<u32>,
}

impl MacosReader {
    pub fn new() -> io::Result<Self> {
        let users = run_dscl(&[".", "-list", "/Users"])?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let groups = run_dscl(&[".", "-list", "/Groups"])?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let uids = run_dscl(&[".", "-list", "/Users", "UniqueID"])?
            .lines()
            .filter_map(parse_uid_line)
            .collect();
        Ok(MacosReader {
            users,
            groups,
            uids,
        })
    }
}

impl Reader for MacosReader {
    fn used_uids(&self) -> Vec<u32> {
        self.uids.clone()
    }

    fn has_user(&self, name: &str) -> bool {
        self.users.contains(name)
    }

    fn has_group(&self, name: &str) -> bool {
        self.groups.contains(name)
    }
}

fn parse_uid_line(line: &str) -> Option<u32> {
    let last = line.split_whitespace().last()?;
    let uid = last.parse::<i32>().ok()?;
    if uid < 0 { None } else { Some(uid as u32) }
}

fn run_dscl(args: &[&str]) -> io::Result<String> {
    let output = Command::new("dscl").args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "dscl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Side-effecting half of the accounts API. Verbs ask in domain terms
/// (`would_create_tenant`, `create_tenant`); the impl owns argv construction
/// and self-emits intent + (verbose) mechanism via the Reporter handed in.
/// Failure surfaces back as `ExecError` for the verb to render and exit on.
pub(crate) trait Writer {
    fn would_create_tenant(&self, name: &str, uid: u32, reporter: &mut Reporter);
    fn create_tenant(&self, name: &str, uid: u32, reporter: &mut Reporter)
    -> Result<(), ExecError>;
}

pub(crate) struct MacosWriter<'a> {
    exec: &'a dyn Executor,
}

impl<'a> MacosWriter<'a> {
    pub(crate) fn new(exec: &'a dyn Executor) -> Self {
        Self { exec }
    }
}

impl<'a> Writer for MacosWriter<'a> {
    fn would_create_tenant(&self, name: &str, uid: u32, reporter: &mut Reporter) {
        let argv = build_create_argv(name, uid);
        reporter.write(messages::would_create_tenant(name, &argv));
    }

    fn create_tenant(
        &self,
        name: &str,
        uid: u32,
        reporter: &mut Reporter,
    ) -> Result<(), ExecError> {
        let argv = build_create_argv(name, uid);
        reporter.write(messages::creating_tenant(name, &argv));
        self.exec.run(&argv)
    }
}

fn build_create_argv(name: &str, uid: u32) -> Vec<String> {
    vec![
        "sudo".into(),
        "sysadminctl".into(),
        "-addUser".into(),
        name.into(),
        "-fullName".into(),
        format!("Tenant: {name}"),
        "-shell".into(),
        "/bin/zsh".into(),
        "-UID".into(),
        uid.to_string(),
        "-GID".into(),
        uid.to_string(),
    ]
}

pub fn validate_name(name: &str) -> Result<(), NameError> {
    let len = name.len();
    if len == 0 {
        return Err(NameError::Empty);
    }
    if len > MAX_NAME_LEN {
        return Err(NameError::TooLong {
            len,
            max: MAX_NAME_LEN,
        });
    }
    let mut chars = name.chars();
    let first = chars.next().expect("len > 0 guarantees at least one char");
    if !first.is_ascii_lowercase() {
        return Err(NameError::InvalidStart(first));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(NameError::InvalidCharacter(c));
        }
    }
    Ok(())
}
