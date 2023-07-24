use super::structs::AllUserPermission;
use anyhow::anyhow;
use anyhow::Result;
use aruna_rust_api::api::storage::models::v2::User;
use diesel_ulid::DieselUlid;
use std::str::FromStr;

pub trait GetPermissions {
    fn get_permissions(&self, token_id: Option<DieselUlid>) -> Result<AllUserPermission>;
}

impl GetPermissions for User {
    fn get_permissions(&self, token_id: Option<DieselUlid>) -> Result<AllUserPermission> {
        let attributes = self
            .attributes
            .clone()
            .ok_or_else(|| anyhow!("Missing user attributes"))?;

        let mut all_user_perm = AllUserPermission {
            perms: vec![],
            user_id: Some(DieselUlid::from_str(self.id.as_str())?),
            is_sa: attributes.service_account,
            is_admin: attributes.global_admin,
        };

        if let Some(t_id) = token_id {
            for t in attributes.tokens {
                if t.id == t_id.to_string() {
                    if let Some(perm) = t.permission {
                        all_user_perm.perms.push(perm.try_into()?);
                        return Ok(all_user_perm);
                    }
                }
            }
        }
        for perm in attributes.personal_permissions {
            all_user_perm.perms.push(perm.try_into()?);
        }
        Ok(all_user_perm)
    }
}
