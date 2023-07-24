use std::str::FromStr;

use anyhow::anyhow;
use aruna_rust_api::api::storage::models::v2::Permission;
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ResWithPerm {
    Project((DieselUlid, PermissionLevel)),
    Collection((DieselUlid, PermissionLevel)),
    Dataset((DieselUlid, PermissionLevel)),
    Object((DieselUlid, PermissionLevel)),
}

impl TryFrom<Permission> for ResWithPerm {
    type Error = anyhow::Error;

    fn try_from(value: Permission) -> Result<Self, Self::Error> {
        Ok(
            match value
                .resource_id
                .ok_or_else(|| anyhow!("Unknown resource_id"))?
            {
                aruna_rust_api::api::storage::models::v2::permission::ResourceId::ProjectId(id) => {
                    ResWithPerm::Project((DieselUlid::from_str(&id)?, value.permission_level()))
                }

                aruna_rust_api::api::storage::models::v2::permission::ResourceId::CollectionId(
                    id,
                ) => {
                    ResWithPerm::Collection((DieselUlid::from_str(&id)?, value.permission_level()))
                }
                aruna_rust_api::api::storage::models::v2::permission::ResourceId::DatasetId(id) => {
                    ResWithPerm::Dataset((DieselUlid::from_str(&id)?, value.permission_level()))
                }
                aruna_rust_api::api::storage::models::v2::permission::ResourceId::ObjectId(id) => {
                    ResWithPerm::Object((DieselUlid::from_str(&id)?, value.permission_level()))
                }
            },
        )
    }
}
