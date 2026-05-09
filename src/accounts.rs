use std::collections::HashSet;
use std::io;
use std::process::Command;

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
