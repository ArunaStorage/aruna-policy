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

pub enum Context {
    Project(ResourcePermission),
    Collection(ResourcePermission),
    Dataset(ResourcePermission),
    Object(ResourcePermission),
    User(DieselUlid),
    GlobalAdmin,
}
