use anyhow::anyhow;
use anyhow::Result;
use aruna_cache::notifications::NotificationCache;
use diesel_ulid::DieselUlid;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::RwLock;

enum Token {
    Oidc(String),
    Regular(DieselUlid),
    DataProxy(Option<DieselUlid>),
}

#[derive(Deserialize, Debug)]
struct KeyCloakResponse {
    #[serde(alias = "realm")]
    _realm: String,
    public_key: String,
    #[serde(alias = "token-service")]
    _token_service: String,
    #[serde(alias = "account-service")]
    _account_service: String,
    #[serde(alias = "tokens-not-before")]
    _tokens_not_before: i64,
}

/// This contains claims for ArunaTokens
/// containing two fields
///
/// - tid: UUID from the specific token
/// - exp: When this token expires (by default very large number)
///
#[derive(Debug, Serialize, Deserialize)]
struct ArunaTokenClaims {
    sub: String,
    subtype: i32,
    uid: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct BasicClaims {
    sub: String,
    exp: usize,
}

pub struct TokenHandler {
    cache: Arc<NotificationCache>,
    oidc_realminfo: String,
    oidc_pubkey: Arc<RwLock<Option<DecodingKey>>>,
}

impl TokenHandler {
    pub fn new(cache: Arc<NotificationCache>, oidc_realminfo: String) -> Self {
        TokenHandler {
            cache,
            oidc_realminfo,
            oidc_pubkey: Arc::new(RwLock::new(None)),
        }
    }

    async fn convert_pubkey_to_decoding_key(&self) -> Result<HashMap<i64, DecodingKey>> {
        pubkey
            .into_iter()
            .map(
                |pubkey| match DecodingKey::from_ed_pem(pubkey.pubkey.as_bytes()) {
                    Ok(e) => Ok((pubkey.id, e)),
                    Err(_) => Err(ArunaError::AuthorizationError(
                        AuthorizationError::PERMISSIONDENIED,
                    )),
                },
            )
            .collect::<Result<HashMap<_, _>, _>>()
    }

    pub async fn validate_oidc_only(&self, token: &str) -> Result<String> {
        let header = decode_header(token)?;

        // Process as keycloak token
        let pem_token = self.get_token_realminfo().await?;
        // Validate key

        let read = {
            let lock = self.oidc_pubkey.try_read().unwrap();
            lock.clone()
        };
        let token_data = match read {
            Some(pk) => decode::<BasicClaims>(token, &pk, &Validation::new(header.alg))?,
            None => decode::<BasicClaims>(
                token,
                &self.get_token_realminfo().await?,
                &Validation::new(header.alg),
            )?,
        };
        let subject = token_data.claims.sub;
        Ok(subject)
    }

    async fn get_token_realminfo(&self) -> Result<DecodingKey> {
        let resp = reqwest::get(&self.oidc_realminfo)
            .await?
            .json::<KeyCloakResponse>()
            .await?;
        let dec_key = DecodingKey::from_rsa_pem(
            format!(
                "{}\n{}\n{}",
                "-----BEGIN PUBLIC KEY-----", resp.public_key, "-----END PUBLIC KEY-----"
            )
            .as_bytes(),
        )?;
        let pks = self.oidc_pubkey.clone();
        let mut lck = pks.write().unwrap();
        *lck = Some(dec_key.clone());
        Ok(dec_key)
    }
}
