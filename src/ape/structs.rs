use std::collections::HashMap;

use diesel_ulid::DieselUlid;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionLevel {
    NONE = 0,
    READ,
    APPEND,
    WRITE,
    ADMIN,
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
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
    Personal,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenSubject {
    pub user_id: DieselUlid,
    pub token_id: DieselUlid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Context {
    pub subject: DieselUlid,
    pub operation: PermissionLevel,
    pub target: ResourceTarget,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Constraints {
    InProject(DieselUlid),
    NotInProject(DieselUlid),
    InCollection(DieselUlid),
    NotInCollection(DieselUlid),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Decision {
    Deny,
    Allow(Vec<Constraints>),
}
