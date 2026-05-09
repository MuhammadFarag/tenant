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
