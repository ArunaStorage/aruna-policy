use anyhow::anyhow;
use anyhow::Result;
use aruna_cache::structs::Resource;
use aruna_cache::structs::ResourcePermission;
use aruna_rust_api::api::storage::models::v2::permission::ResourceId;
use aruna_rust_api::api::storage::models::v2::User;
use diesel_ulid::DieselUlid;
use std::str::FromStr;

use super::structs::ResWithPerm;

pub trait GetPermissions {
    fn get_permissions(&self, token_id: Option<DieselUlid>) -> Result<Vec<ResWithPerm>>;
}

impl GetPermissions for User {
    fn get_permissions(&self, token_id: Option<DieselUlid>) -> Result<Vec<ResWithPerm>> {
        let attributes = self
            .attributes
            .ok_or_else(|| anyhow!("Missing user attributes"))?;

        if let Some(t_id) = token_id {
            for t in attributes.tokens {
                if t.id == t_id.to_string() {
                    if let Some(perm) = t.permission {
                        if let Some(p) = perm.resource_id {
                            match p {
                                ResourceId::ProjectId(res) => {
                                    return Ok(vec![(
                                        ResourcePermission::Resource(Resource::Project(
                                            DieselUlid::from_str(&res)?,
                                        )),
                                        perm.permission_level(),
                                    )])
                                }
                                ResourceId::CollectionId(res) => {
                                    return Ok(vec![(
                                        ResourcePermission::Resource(Resource::Collection(
                                            DieselUlid::from_str(&res)?,
                                        )),
                                        perm.permission_level(),
                                    )])
                                }
                                ResourceId::DatasetId(res) => {
                                    return Ok(vec![(
                                        ResourcePermission::Resource(Resource::Dataset(
                                            DieselUlid::from_str(&res)?,
                                        )),
                                        perm.permission_level(),
                                    )])
                                }
                                ResourceId::ObjectId(res) => {
                                    return Ok(vec![(
                                        ResourcePermission::Resource(Resource::Object(
                                            DieselUlid::from_str(&res)?,
                                        )),
                                        perm.permission_level(),
                                    )])
                                }
                            }
                        }
                    }
                }
            }
        }

        // Process "personal" permissions

        for perm in attributes.personal_permissions {}

        Ok(vec![])
    }
}
