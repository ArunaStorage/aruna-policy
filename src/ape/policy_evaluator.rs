use std::sync::Arc;

use crate::token::token_handler::TokenHandler;

use super::structs::Context;
use anyhow::{anyhow, Result};
use aruna_cache::{
    notifications::NotificationCache,
    query::QueryHandler,
    structs::{Resource, ResourcePermission},
};
use aruna_rust_api::api::storage::models::v2::{PermissionLevel, Token};
use diesel_ulid::DieselUlid;

struct PolicyEvaluator {
    cache: Arc<NotificationCache>,
    token_handler: TokenHandler,
}

impl PolicyEvaluator {
    pub async fn new(
        client_token: &str,
        server_addr: &str,
        qhandler: Box<dyn QueryHandler + Send + Sync>,
    ) -> Result<Self> {
        let cache = Arc::new(NotificationCache::new(client_token, server_addr, qhandler).await?);

        Ok(PolicyEvaluator {
            cache: Arc::new(NotificationCache::new(client_token, server_addr, qhandler).await?),
            token_handler: TokenHandler::new(cache.clone()),
        })
    }

    pub async fn check_permissions(&self, token: &str, ctx: Context) -> Result<DieselUlid> {
        let permissions: Vec<(ResourcePermission, PermissionLevel)> = Vec::new();

        let (ok, constraints) = self.filter_perms(permissions, ctx)?;

        if !ok {
            return Err(anyhow!("Invalid permissions"));
        }

        //self.cache.;

        Err(anyhow!("Invalid permissions"))
    }

    fn filter_perms(
        &self,
        perms: Vec<(ResourcePermission, PermissionLevel)>,
        ctx: Context,
    ) -> Result<(bool, Vec<Resource>)> {
        let mut required_res = Vec::new();
        for (rp, lvl) in perms {
            // GlobalAdmins are always welcome
            if rp == ResourcePermission::GlobalAdmin {
                return Ok((true, vec![]));
            }

            match &ctx {
                Context::Project(ctx_rp)
                | Context::Collection(ctx_rp)
                | Context::Dataset(ctx_rp)
                | Context::Object(ctx_rp) => {
                    if !ctx_rp.allow_sa && rp == ResourcePermission::ServiceAccount
                        || ctx_rp.level > lvl.into()
                    {
                        return Ok((false, vec![]));
                    }
                    match rp {
                        ResourcePermission::Resource(res) => {
                            if res.get_id() == ctx_rp.id {
                                return Ok((false, vec![]));
                            } else {
                                required_res.push(res)
                            }
                        }
                        _ => (),
                    }
                }
                Context::User(ctx_rp) => todo!(), // Associate SA / Token with user_id in cache ?
                Context::GlobalAdmin => (),
            }
        }
        if required_res.is_empty() {
            Ok((false, vec![]))
        } else {
            Ok((true, required_res))
        }
    }
}
