use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EntityType {
    Ip,
    User,
    Container,
    Path,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EntityRef {
    pub r#type: EntityType,
    pub value: String,
}

impl EntityRef {
    pub fn ip(v: impl Into<String>) -> Self {
        Self {
            r#type: EntityType::Ip,
            value: v.into(),
        }
    }
    pub fn user(v: impl Into<String>) -> Self {
        Self {
            r#type: EntityType::User,
            value: v.into(),
        }
    }
    pub fn container(v: impl Into<String>) -> Self {
        Self {
            r#type: EntityType::Container,
            value: v.into(),
        }
    }
    pub fn path(v: impl Into<String>) -> Self {
        Self {
            r#type: EntityType::Path,
            value: v.into(),
        }
    }
    pub fn service(v: impl Into<String>) -> Self {
        Self {
            r#type: EntityType::Service,
            value: v.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_ref_constructors() {
        let ip = EntityRef::ip("1.2.3.4");
        assert_eq!(ip.r#type, EntityType::Ip);
        assert_eq!(ip.value, "1.2.3.4");

        let user = EntityRef::user("root");
        assert_eq!(user.r#type, EntityType::User);
        assert_eq!(user.value, "root");

        let container = EntityRef::container("abcdef123456");
        assert_eq!(container.r#type, EntityType::Container);
        assert_eq!(container.value, "abcdef123456");

        let path = EntityRef::path("/etc/passwd");
        assert_eq!(path.r#type, EntityType::Path);
        assert_eq!(path.value, "/etc/passwd");

        let service = EntityRef::service("sshd");
        assert_eq!(service.r#type, EntityType::Service);
        assert_eq!(service.value, "sshd");
    }

    #[test]
    fn test_entity_type_serialization() {
        assert_eq!(serde_json::to_string(&EntityType::Ip).unwrap(), "\"ip\"");
        assert_eq!(
            serde_json::to_string(&EntityType::Container).unwrap(),
            "\"container\""
        );
    }
}
