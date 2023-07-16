use super::structs::Context;
use anyhow::Result;
use aruna_cache::{notifications::NotificationCache, structs::ResourcePermission};
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
    ) -> Result<bool> {
        for (rp, lvl) in perms {
            if rp == ResourcePermission::GlobalAdmin {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
