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

#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    InvalidStart(char),
    InvalidCharacter(char),
    TooLong { len: usize, max: usize },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_simple_name() {
        assert!(validate_name("dev").is_ok());
    }

    #[test]
    fn empty_name() {
        assert_eq!(validate_name(""), Err(NameError::Empty));
    }

    #[test]
    fn non_letter_start() {
        for name in ["1dev", "_dev", "-dev", "Dev"] {
            assert!(
                matches!(validate_name(name), Err(NameError::InvalidStart(_))),
                "expected InvalidStart for {name:?}, got {:?}",
                validate_name(name),
            );
        }
    }

    #[test]
    fn invalid_character() {
        for name in ["de v", "de@v", "dev."] {
            assert!(
                matches!(validate_name(name), Err(NameError::InvalidCharacter(_))),
                "expected InvalidCharacter for {name:?}, got {:?}",
                validate_name(name),
            );
        }
    }

    #[test]
    fn length_at_limit() {
        let name = "a".repeat(MAX_NAME_LEN);
        assert!(validate_name(&name).is_ok());
    }

    #[test]
    fn length_over_limit() {
        let name = "a".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            validate_name(&name),
            Err(NameError::TooLong {
                len: MAX_NAME_LEN + 1,
                max: MAX_NAME_LEN,
            }),
        );
    }

    #[test]
    fn single_letter() {
        assert!(validate_name("x").is_ok());
    }
}
