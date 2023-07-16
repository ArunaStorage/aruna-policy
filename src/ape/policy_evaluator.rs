use super::structs::Context;
use anyhow::Result;
use aruna_cache::{
    notifications::NotificationCache,
    structs::{Resource, ResourcePermission},
};
use aruna_rust_api::api::storage::models::v2::PermissionLevel;
use diesel_ulid::DieselUlid;

struct PolicyEvaluator {
    cache: NotificationCache,
}

enum Token {
    Oidc(String),
    Regular(DieselUlid),
}

impl PolicyEvaluator {
    pub async fn new(client_token: &str, server_addr: &str) -> Result<Self> {
        Ok(PolicyEvaluator {
            cache: NotificationCache::new(client_token, server_addr).await?,
        })
    }

    pub async fn check_permissions(&self, token: &str, ctx: Context) -> Result<bool> {
        let permissions: Vec<(ResourcePermission, PermissionLevel)> =
            match self.extract_token(token).await {
                Token::Oidc(oidc) => todo!(), //self.cache.,
                Token::Regular(ulid) => todo!(),
            };

        //self.cache.;

        Ok(false)
    }

    pub async fn extract_token(&self, _token: &str) -> Token {
        Token::Oidc("A test_token".to_string())
    }

    pub fn filter_perms(
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
        }else{
            Ok((true, required_res))
        }
        
    }
}
