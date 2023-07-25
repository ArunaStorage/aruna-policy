use super::{
    permissions::GetPermissions,
    structs::{AllUserPermission, Context},
};
use crate::token::token_handler::TokenHandler;
use anyhow::{anyhow, Result};
use aruna_cache::notifications::NotificationCache;
use diesel_ulid::DieselUlid;
use std::{collections::HashSet, sync::Arc};

pub struct PolicyEvaluator {
    cache: Arc<NotificationCache>,
    token_handler: TokenHandler,
}

impl PolicyEvaluator {
    pub async fn new(oidc_realminfo: &str, cache: Arc<NotificationCache>) -> Result<Self> {
        Ok(PolicyEvaluator {
            cache: cache.clone(),
            token_handler: TokenHandler::new(cache.clone(), oidc_realminfo.to_string()),
        })
    }

    pub async fn check_multi_context(
        &self,
        token: &str,
        ctxs: Vec<Context>,
    ) -> Result<Option<DieselUlid>> {
        let (user_id, token_id) = self.token_handler.process_token(token).await?;

        let perms = if let Some(uid) = user_id {
            self.get_user_permissions(uid, token_id)?
        } else {
            AllUserPermission::default()
        };

        let mut ress = Vec::new();
        let mut outer_constraints = HashSet::new();
        for ctx in ctxs {
            let (ok, rescon) = perms.compare_ctx(ctx);

            if !ok {
                return Err(anyhow!("Invalid permissions"));
            }

            if let Some((res, constraints)) = rescon {
                ress.push(res);
                outer_constraints.extend(constraints);
            }
        }

        if !outer_constraints.is_empty() {
            self.cache.cache.check_from_multi_with_targets(
                ress.iter().collect(),
                outer_constraints.into_iter().collect(),
            )?;
        }

        Ok(user_id)
    }

    pub async fn check_context(&self, token: &str, ctx: Context) -> Result<Option<DieselUlid>> {
        let (user_id, token_id) = self.token_handler.process_token(token).await?;

        let perms = if let Some(uid) = user_id {
            self.get_user_permissions(uid, token_id)?
        } else {
            AllUserPermission::default()
        };

        let (ok, rescon) = perms.compare_ctx(ctx);

        if !ok {
            return Err(anyhow!("Invalid permissions"));
        }

        if let Some((res, constraints)) = rescon {
            self.cache
                .cache
                .check_with_targets(&res, constraints.into_iter().collect())?;
        }

        Ok(user_id)
    }

    fn get_user_permissions(
        &self,
        user: DieselUlid,
        token: Option<DieselUlid>,
    ) -> Result<AllUserPermission> {
        let user = self
            .cache
            .cache
            .get_user(user)
            .ok_or_else(|| anyhow!("User not found"))?;
        user.get_permissions(token)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_filter_perms() {}
    //     // Create a sample resource permission
    //     let resource_permission = ApeResourcePermission {
    //         id: DieselUlid::generate(),
    //         level: PermissionLevels::ADMIN,
    //         allow_sa: true,
    //     };

    //     // Create a sample user ID
    //     let user_id = Some(DieselUlid::generate());

    //     // Test case 1: GlobalAdmin should always return true
    //     let result = filter_perms(
    //         vec![(ResourcePermission::GlobalAdmin, PermissionLevel::Admin)],
    //         user_id,
    //         false,
    //         Context::GlobalAdmin,
    //     );
    //     assert_eq!(result, (true, vec![]));

    //     // Test case 2: User context matches user ID and not a service account
    //     let result = filter_perms(
    //         vec![(
    //             ResourcePermission::Resource(Resource::Object(DieselUlid::generate())),
    //             PermissionLevel::Write,
    //         )],
    //         user_id,
    //         false,
    //         Context::User(ApeUserPermission {
    //             id: user_id.unwrap(),
    //             allow_proxy: false,
    //         }),
    //     );
    //     assert_eq!(result, (true, vec![]));

    //     // Test case 3: User context matches user ID but is a service account (not allowed)
    //     let result = filter_perms(
    //         vec![(
    //             ResourcePermission::Resource(Resource::Object(DieselUlid::generate())),
    //             PermissionLevel::Admin,
    //         )],
    //         user_id,
    //         true,
    //         Context::User(ApeUserPermission {
    //             id: user_id.unwrap(),
    //             allow_proxy: false,
    //         }),
    //     );
    //     assert_eq!(result, (false, vec![]));

    //     // Test case 4: User context does not match user ID
    //     let result = filter_perms(
    //         vec![(
    //             ResourcePermission::Resource(Resource::Object(DieselUlid::generate())),
    //             PermissionLevel::Admin,
    //         )],
    //         Some(DieselUlid::generate()),
    //         false,
    //         Context::User(ApeUserPermission {
    //             id: user_id.unwrap(),
    //             allow_proxy: false,
    //         }),
    //     );
    //     assert_eq!(result, (false, vec![]));

    //     // Test case 5: Context matches resource ID, and level is sufficient
    //     let result = filter_perms(
    //         vec![(
    //             ResourcePermission::Resource(Resource::Object(resource_permission.clone().id)),
    //             PermissionLevel::Admin,
    //         )],
    //         user_id,
    //         false,
    //         Context::ResourceContext(ResourceContext::Object(resource_permission.clone())),
    //     );
    //     assert_eq!(result, (true, vec![]));

    //     // Test case 6: Context matches resource ID, but level is insufficient
    //     let result = filter_perms(
    //         vec![(
    //             ResourcePermission::Resource(Resource::Object(resource_permission.clone().id)),
    //             PermissionLevel::Read,
    //         )],
    //         user_id,
    //         false,
    //         Context::ResourceContext(ResourceContext::Object(resource_permission.clone())),
    //     );
    //     assert_eq!(result, (false, vec![]));

    //     // Test case 7: Context does not match resource ID
    //     let ulid = DieselUlid::generate();
    //     let result = filter_perms(
    //         vec![(
    //             ResourcePermission::Resource(Resource::Object(ulid)),
    //             PermissionLevel::Write,
    //         )],
    //         user_id,
    //         false,
    //         Context::ResourceContext(ResourceContext::Object(ApeResourcePermission {
    //             id: DieselUlid::generate(),
    //             level: PermissionLevels::ADMIN,
    //             allow_sa: true,
    //         })),
    //     );
    //     assert_eq!(result, (true, vec![Resource::Object(ulid)]));

    //     // Test case 8: Context is a service account and service accounts are not allowed
    //     let result = filter_perms(
    //         vec![(ResourcePermission::ServiceAccount, PermissionLevel::Admin)],
    //         user_id,
    //         true,
    //         Context::ResourceContext(ResourceContext::Object(resource_permission.clone())),
    //     );
    //     assert_eq!(result, (false, vec![]));
    // }
}
