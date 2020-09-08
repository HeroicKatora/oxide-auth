use r2d2_redis::RedisConnectionManager;
use r2d2::Pool;
use std::env;
use r2d2_redis::redis::Commands;
use oxide_auth::primitives::registrar::{EncodedClient, ClientType};
use crate::primitives::db_registrar::OauthClientDBRepository;
use dotenv::dotenv;
use url::Url;
use oxide_auth::primitives::prelude::Scope;
use std::str::FromStr;

pub const REDIS_POOL_SIZE: u32 = 32;

/// redis datasource to Client entries.

#[derive(Debug, Clone)]
pub struct RedisDataSource {
    pub url: String,
    pub pool: Pool<RedisConnectionManager>,
}

impl RedisDataSource {

    pub fn new() -> Self {
        dotenv().ok();
        let url = env::var("REDIS_URL").expect("REDIS_URL must be set");
        let pool = REDIS_POOL.clone();
        RedisDataSource { url, pool }
    }

    pub fn get_url(&self) -> String {
        self.url.to_string()
    }
    pub fn get_pool(self) -> Pool<RedisConnectionManager> {
        self.pool
    }
}


lazy_static! {
    pub static ref REDIS_POOL: r2d2::Pool<r2d2_redis::RedisConnectionManager> = {
        dotenv::dotenv().ok();
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
        let manager = r2d2_redis::RedisConnectionManager::new(redis_url).unwrap();
        let max_pool_size: u32 = env::var("REDIS_POOL_SIZE")
            .unwrap_or_else(|_| REDIS_POOL_SIZE.to_string())
            .parse::<u32>()
            .unwrap_or(REDIS_POOL_SIZE);

        r2d2::Pool::builder()
            .max_size(max_pool_size)
            .build(manager)
            .expect("Failed to create redis pool.")
    };

}

/// A client whose credentials have been wrapped by a password policy.
///
/// This provides a standard encoding for `Registrars` who wish to store their clients and makes it
/// possible to test password policies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringfiedEncodedClient {
    /// The id of this client. If this is was registered at a `Registrar`, this should be a key
    /// to the instance.
    pub client_id: String,

    /// The registered redirect uri.
    /// Unlike `additional_redirect_uris`, this is registered as the default redirect uri
    /// and will be replaced if, for example, no `redirect_uri` is specified in the request parameter.
    pub redirect_uri: String,

    /// The redirect uris that can be registered in addition to the `redirect_uri`.
    /// If you want to register multiple redirect uris, register them together with `redirect_uri`.
    pub additional_redirect_uris: Vec<String>,

    /// The scope the client gets if none was given.
    pub default_scope: Option<String>,

    /// client_secret, for authentication.
    pub client_secret: Option<String>,
}

impl StringfiedEncodedClient {
    pub fn to_encoded_client(&self) -> EncodedClient {
        let redirect_uri =  Url::parse(&self.redirect_uri).unwrap();
        let uris =  &self.additional_redirect_uris;
        let additional_redirect_uris = uris.into_iter().fold(vec![], |mut us, u| { us.push(Url::parse(u).unwrap()); us});
        let client_type = match &self.client_secret {
            None => ClientType::Public,
            Some(secret) => ClientType::Confidential {passdata: secret.to_owned().into_bytes()},
        };
        EncodedClient{
            client_id: (&self.client_id).parse().unwrap(),
            redirect_uri,
            additional_redirect_uris,
            default_scope: Scope::from_str(self.default_scope.as_ref().unwrap_or(&"".to_string()).as_ref()).unwrap(),
            encoded_client: client_type
        }
    }

    pub fn from_encoded_client(encoded_client: &EncodedClient) -> Self {
        let additional_redirect_uris = encoded_client.additional_redirect_uris
            .iter()
            .map(|u| u.to_owned().into_string())
            .collect();
        let default_scope = Some(encoded_client.default_scope.to_string());
        let client_secret = match &encoded_client.encoded_client{
            ClientType::Public => None,
            ClientType::Confidential { passdata} => Some(String::from_utf8(passdata.to_vec()).unwrap())
        };
        StringfiedEncodedClient{
            client_id: encoded_client.client_id.to_owned(),
            redirect_uri: encoded_client.redirect_uri.to_owned().into_string(),
            additional_redirect_uris,
            default_scope,
            client_secret
        }
    }
}


impl RedisDataSource {
    /// users can regist to redis a custom client struct which can be Serialized and Deserialized.
    pub fn regist_from_stringfied_encoded_client(&self, detail: &StringfiedEncodedClient) -> anyhow::Result<()>{
        let mut pool = self.pool.get().unwrap();
        let client_str = serde_json::to_string(&detail)?;
        pool.set(&detail.client_id, client_str)?;
        Ok(())
    }
}

impl OauthClientDBRepository for RedisDataSource{
    fn list(&self, salt: String) -> anyhow::Result<Vec<EncodedClient>> {
        unimplemented!()
    }

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient> {
        let mut r = self.pool.get().unwrap();
        let client_str = r.get::<&str, String>(id)?;
        let stringfied_client = serde_json::from_str::<StringfiedEncodedClient>(&client_str)?;
        Ok(stringfied_client.to_encoded_client())
    }

    fn regist_from_encoded_client(&self, client: EncodedClient)  -> anyhow::Result<()>{
        let mut pool = self.pool.get().unwrap();
        let detail = StringfiedEncodedClient::from_encoded_client(&client);
        self.regist_from_stringfied_encoded_client(&detail)
    }

}

