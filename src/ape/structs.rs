use diesel_ulid::DieselUlid;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub enum PermissionLevel {
    #[default]
    NONE = 0,
    READ,
    APPEND,
    WRITE,
    ADMIN,
}

impl From<i32> for PermissionLevel {
    fn from(value: i32) -> Self {
        match value {
            1 => Self::READ,
            2 => Self::APPEND,
            3 => Self::WRITE,
            4 => Self::ADMIN,
            _ => Self::NONE,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DenieablePerms {
    pub allow: HashMap<DieselUlid, PermissionLevel>,
    pub deny: Vec<DieselUlid>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TokenPermissions {
    Project((DieselUlid, PermissionLevel)),
    Collection((DieselUlid, PermissionLevel)),
    Personal,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UserAttributes {
    pub global_admin: bool,
    pub service_account: bool,
    pub projects: HashMap<DieselUlid, PermissionLevel>,
    pub collections: DenieablePerms,
    pub objects: DenieablePerms,
    pub tokens: HashMap<DieselUlid, TokenPermissions>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ResourceTarget {
    Object(DieselUlid),
    Collection(DieselUlid),
    Project(DieselUlid),
    GlobalAdmin,
    Personal(DieselUlid),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenSubject {
    pub user_id: DieselUlid,
    pub token_id: DieselUlid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Context {
    pub subject: TokenSubject,
    pub operation: PermissionLevel,
    pub target: ResourceTarget,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Constraint {
    InProject(DieselUlid),
    InCollection(DieselUlid),
    NotInCollection(DieselUlid),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Deny,
    Allow(Vec<Constraint>),
}
