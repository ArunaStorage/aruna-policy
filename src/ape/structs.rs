use std::collections::HashSet;
use std::str::FromStr;

use anyhow::anyhow;
use aruna_cache::structs::Resource;
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

impl Context {
    pub fn empty() -> Self {
        Context::Empty
    }

    pub fn res_proj(res_perm: Option<(DieselUlid, PermissionLevels, bool)>) -> Self {
        Context::ResourceContext(ResourceContext::Project(
            res_perm.map(|p| ApeResourcePermission::new(p.0, p.1, p.2)),
        ))
    }

    pub fn res_col(id: DieselUlid, level: PermissionLevels, allow_sa: bool) -> Self {
        Context::ResourceContext(ResourceContext::Collection(ApeResourcePermission::new(
            id, level, allow_sa,
        )))
    }

    pub fn res_ds(id: DieselUlid, level: PermissionLevels, allow_sa: bool) -> Self {
        Context::ResourceContext(ResourceContext::Dataset(ApeResourcePermission::new(
            id, level, allow_sa,
        )))
    }

    pub fn res_obj(id: DieselUlid, level: PermissionLevels, allow_sa: bool) -> Self {
        Context::ResourceContext(ResourceContext::Object(ApeResourcePermission::new(
            id, level, allow_sa,
        )))
    }

    pub fn user(id: DieselUlid, allow_proxy: bool) -> Self {
        Context::User(ApeUserPermission { id, allow_proxy })
    }

    pub fn admin() -> Self {
        Context::GlobalAdmin
    }
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
                .clone()
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct AllUserPermission {
    pub perms: Vec<ResWithPerm>,
    pub user_id: Option<DieselUlid>,
    pub is_sa: bool,
    pub is_admin: bool,
}

impl AllUserPermission {
    fn check_single_perm(&self, perm: ApeResourcePermission) -> (bool, Option<HashSet<Resource>>) {
        if perm.allow_sa && self.is_sa {
            return (true, None);
        }
        let mut constraints = HashSet::new();

        for x in self.perms.iter() {
            match x {
                ResWithPerm::Project((id, lvl)) => {
                    if PermissionLevels::from(*lvl) >= perm.level {
                        if id == &perm.id {
                            return (true, None);
                        } else {
                            constraints.insert(Resource::Project(id.clone()));
                        }
                    }
                }
                ResWithPerm::Collection((id, lvl)) => {
                    if PermissionLevels::from(*lvl) >= perm.level {
                        if id == &perm.id {
                            return (true, None);
                        } else {
                            constraints.insert(Resource::Project(id.clone()));
                        }
                    }
                }
                ResWithPerm::Dataset((id, lvl)) => {
                    if PermissionLevels::from(*lvl) >= perm.level {
                        if id == &perm.id {
                            return (true, None);
                        } else {
                            constraints.insert(Resource::Project(id.clone()));
                        }
                    }
                }
                ResWithPerm::Object((id, lvl)) => {
                    if PermissionLevels::from(*lvl) >= perm.level {
                        if id == &perm.id {
                            return (true, None);
                        } else {
                            constraints.insert(Resource::Project(id.clone()));
                        }
                    }
                }
            }
        }
        if constraints.is_empty() {
            (false, None)
        } else {
            (true, Some(constraints))
        }
    }

    pub fn compare_ctx(&self, ctx: Context) -> (bool, Option<(Resource, HashSet<Resource>)>) {
        match ctx {
            Context::GlobalAdmin => {
                if self.is_admin {
                    (true, None)
                } else {
                    (false, None)
                }
            }
            Context::Empty => (true, None),
            Context::ResourceContext(res_ctx) => match res_ctx {
                ResourceContext::Project(pperm) => {
                    if let Some(perm) = pperm {
                        let (ok, constraints) = self.check_single_perm(perm.clone());
                        return (ok, constraints.map(|x| (Resource::Project(perm.id), x)));
                    } else {
                        (true, None)
                    }
                }
                ResourceContext::Collection(cperm) => {
                    let (ok, constraints) = self.check_single_perm(cperm.clone());
                    return (ok, constraints.map(|x| (Resource::Collection(cperm.id), x)));
                }
                ResourceContext::Dataset(dperm) => {
                    let (ok, constraints) = self.check_single_perm(dperm.clone());
                    return (ok, constraints.map(|x| (Resource::Collection(dperm.id), x)));
                }
                ResourceContext::Object(operm) => {
                    let (ok, constraints) = self.check_single_perm(operm.clone());
                    return (ok, constraints.map(|x| (Resource::Collection(operm.id), x)));
                }
            },
            Context::User(uid) => match self.user_id {
                Some(id) => {
                    if id == uid.id {
                        (true, None)
                    } else {
                        (false, None)
                    }
                }
                None => {
                    if uid.allow_proxy {
                        (true, None)
                    } else {
                        (false, None)
                    }
                }
            },
        }
    }
}
