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
                        return Ok(vec![perm.try_into()?]);
                    }
                }
            }
        }

        // Process "personal" permissions
        let mut result = vec![];
        if attributes.global_admin {
            result.push(ResWithPerm::GlobalAdmin);
        }
        if !attributes.service_account {
            result.push(ResWithPerm::User(DieselUlid::from_str(self.id.as_str())?));
        }
        for perm in attributes.personal_permissions {
            result.push(perm.try_into()?);
        }

        Ok(result)
    }
}
