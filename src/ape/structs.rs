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
pub struct ApeResourcePermission {
    pub id: DieselUlid,
    pub level: PermissionLevels,
    pub allow_sa: bool,
}

impl ApeResourcePermission {
    pub fn new(id: DieselUlid, level: PermissionLevels, allow_sa: bool) -> Self {
        ApeResourcePermission {
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ApeUserPermission {
    pub id: DieselUlid,
    pub allow_proxy: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ResourceContext {
    Project(Option<ApeResourcePermission>),
    Collection(ApeResourcePermission),
    Dataset(ApeResourcePermission),
    Object(ApeResourcePermission),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Context {
    Empty,
    ResourceContext(ResourceContext),
    User(ApeUserPermission),
    GlobalAdmin,
}
