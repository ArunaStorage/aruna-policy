use aruna_rust_api::api::storage::models::v2::PermissionLevel;
use diesel_ulid::DieselUlid;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum PermissionLevels {
    DENY,
    NONE,
    READ,
    APPEND,
    WRITE,
    ADMIN,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ResourcePermission {
    pub id: DieselUlid,
    pub level: PermissionLevels,
    pub allow_sa: bool,
}

impl ResourcePermission {
    pub fn new(id: DieselUlid, level: PermissionLevels, allow_sa: bool) -> Self {
        ResourcePermission {
            id,
            level,
            allow_sa,
        }
    }
}

impl From<PermissionLevel> for PermissionLevels {
    fn from(value: PermissionLevel) -> Self {
        match &value {
            PermissionLevel::Unspecified => PermissionLevels::DENY,
            PermissionLevel::None => PermissionLevels::NONE,
            PermissionLevel::Read => PermissionLevels::READ,
            PermissionLevel::Append => PermissionLevels::APPEND,
            PermissionLevel::Write => PermissionLevels::WRITE,
            PermissionLevel::Admin => PermissionLevels::ADMIN,
        }
    }
}

pub enum Context {
    Project(ResourcePermission),
    Collection(ResourcePermission),
    Dataset(ResourcePermission),
    Object(ResourcePermission),
    User(DieselUlid),
    GlobalAdmin,
}
