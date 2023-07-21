use std::sync::Arc;

use crate::token::token_handler::TokenHandler;

use super::structs::Context;
use anyhow::{anyhow, Result};
use aruna_cache::{
    notifications::NotificationCache,
    query::QueryHandler,
    structs::{Resource, ResourcePermission},
};
use aruna_rust_api::api::storage::models::v2::PermissionLevel;
use diesel_ulid::DieselUlid;

struct PolicyEvaluator {
    cache: Arc<NotificationCache>,
    token_handler: TokenHandler,
}

impl PolicyEvaluator {
    pub async fn new(
        client_token: &str,
        server_addr: &str,
        oidc_realminfo: &str,
        qhandler: Box<dyn QueryHandler + Send + Sync>,
    ) -> Result<Self> {
        let cache = Arc::new(NotificationCache::new(client_token, server_addr, qhandler).await?);
        Ok(PolicyEvaluator {
            cache: cache.clone(),
            token_handler: TokenHandler::new(cache.clone(), oidc_realminfo.to_string()),
        })
    }

    pub async fn check_permissions(&self, token: &str, ctx: Context) -> Result<Option<DieselUlid>> {
        let (user_id, token_id, is_proxy) = self.token_handler.process_token(token).await?;

        let perms = if let Some(token) = token_id {
            self.cache
                .cache
                .get_permissions(&token)
                .ok_or(anyhow!("permissions not found"))?
        } else {
            vec![]
        };

        let (ok, _constraints) = filter_perms(perms, user_id, is_proxy, ctx);

        if !ok {
            return Err(anyhow!("Invalid permissions"));
        }

        //self.cache.;
        Ok(user_id)
    }
}
fn filter_perms(
    perms: Vec<(ResourcePermission, PermissionLevel)>,
    user_id: Option<DieselUlid>,
    is_service_account: bool,
    ctx: Context,
) -> (bool, Vec<Resource>) {
    let mut constraints = Vec::new();
    for (rp, lvl) in perms {
        // GlobalAdmins are always welcome
        if rp == ResourcePermission::GlobalAdmin {
            return (true, vec![]);
        }

        match &ctx {
            Context::Project(Some(ctx_rp))
            | Context::Collection(ctx_rp)
            | Context::Dataset(ctx_rp)
            | Context::Object(ctx_rp) => {
                if !ctx_rp.allow_sa && rp == ResourcePermission::ServiceAccount {
                    return (false, vec![]);
                }

                if let ResourcePermission::Resource(res) = rp {
                    if res.get_id() == ctx_rp.id {
                        if ctx_rp.level > lvl.into() {
                            return (false, vec![]);
                        } else {
                            return (true, vec![]);
                        }
                    } else {
                        constraints.push(res)
                    }
                }
            }
            Context::User(ctx_rp) => {
                if let Some(uid) = user_id {
                    if uid == ctx_rp.id && !is_service_account {
                        return (true, vec![]);
                    } else {
                        return (false, vec![]);
                    }
                } else {
                    return (false, vec![]);
                }
            }
            Context::Project(None) => todo!(), // Associate SA / Token with user_id in cache ?
            Context::GlobalAdmin => (),
        }
    }
    if constraints.is_empty() {
        (false, vec![])
    } else {
        (true, constraints)
    }
}

#[cfg(test)]
mod tests {
    use aruna_rust_api::api::storage::services::v2::UserPermission;

    use super::*;
    use crate::ape::structs::{ApeResourcePermission, ApeUserPermission, PermissionLevels};

    #[test]
    fn test_filter_perms() {
        // Create a sample resource permission
        let resource_permission = ApeResourcePermission {
            id: DieselUlid::generate(),
            level: PermissionLevels::ADMIN,
            allow_sa: true,
        };

        // Create a sample user ID
        let user_id = Some(DieselUlid::generate());

        // Test case 1: GlobalAdmin should always return true
        let result = filter_perms(
            vec![(ResourcePermission::GlobalAdmin, PermissionLevel::Admin)],
            user_id,
            false,
            Context::GlobalAdmin,
        );
        assert_eq!(result, (true, vec![]));

        // Test case 2: User context matches user ID and not a service account
        let result = filter_perms(
            vec![(
                ResourcePermission::Resource(Resource::Object(DieselUlid::generate())),
                PermissionLevel::Write,
            )],
            user_id,
            false,
            Context::User(ApeUserPermission {
                id: user_id.unwrap(),
                allow_proxy: false,
            }),
        );
        assert_eq!(result, (true, vec![]));

        // Test case 3: User context matches user ID but is a service account (not allowed)
        let result = filter_perms(
            vec![(
                ResourcePermission::Resource(Resource::Object(DieselUlid::generate())),
                PermissionLevel::Admin,
            )],
            user_id,
            true,
            Context::User(ApeUserPermission {
                id: user_id.unwrap(),
                allow_proxy: false,
            }),
        );
        assert_eq!(result, (false, vec![]));

        // Test case 4: User context does not match user ID
        let result = filter_perms(
            vec![(
                ResourcePermission::Resource(Resource::Object(DieselUlid::generate())),
                PermissionLevel::Admin,
            )],
            Some(DieselUlid::generate()),
            false,
            Context::User(ApeUserPermission {
                id: user_id.unwrap(),
                allow_proxy: false,
            }),
        );
        assert_eq!(result, (false, vec![]));

        // Test case 5: Context matches resource ID, and level is sufficient
        let result = filter_perms(
            vec![(
                ResourcePermission::Resource(Resource::Object(resource_permission.clone().id)),
                PermissionLevel::Admin,
            )],
            user_id,
            false,
            Context::Object(resource_permission.clone()),
        );
        assert_eq!(result, (true, vec![]));

        // Test case 6: Context matches resource ID, but level is insufficient
        let result = filter_perms(
            vec![(
                ResourcePermission::Resource(Resource::Object(resource_permission.clone().id)),
                PermissionLevel::Read,
            )],
            user_id,
            false,
            Context::Object(resource_permission.clone()),
        );
        assert_eq!(result, (false, vec![]));

        // Test case 7: Context does not match resource ID
        let ulid = DieselUlid::generate();
        let result = filter_perms(
            vec![(
                ResourcePermission::Resource(Resource::Object(ulid)),
                PermissionLevel::Write,
            )],
            user_id,
            false,
            Context::Object(ApeResourcePermission {
                id: DieselUlid::generate(),
                level: PermissionLevels::ADMIN,
                allow_sa: true,
            }),
        );
        assert_eq!(result, (true, vec![Resource::Object(ulid)]));

        // Test case 8: Context is a service account and service accounts are not allowed
        let result = filter_perms(
            vec![(ResourcePermission::ServiceAccount, PermissionLevel::Admin)],
            user_id,
            true,
            Context::Object(resource_permission.clone()),
        );
        assert_eq!(result, (false, vec![]));
    }
}
