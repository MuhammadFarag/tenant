pub(crate) struct Message {
    pub summary: Option<String>,
    pub detail: Option<String>,
}

pub(crate) fn would_create_tenant(name: &str, uid: u32) -> Message {
    Message {
        summary: Some(format!("Would create tenant '{name}'.")),
        detail: Some(format!(
            "Would run:\n  sudo sysadminctl -addUser {name} \
             -fullName \"Tenant: {name}\" -shell /bin/zsh -UID {uid} -GID {uid}"
        )),
    }
}
