use url::quirks::password;
use std::borrow::Borrow;
use std::str::FromStr;
use reqwest::Url;
// use super::scope::Scope;
use oxide_auth::primitives::prelude::{Scope, ClientUrl, PreGrant};

use std::borrow::Cow;
use std::{cmp, env};
use std::collections::HashMap;
use std::fmt;
use std::iter::{Extend, FromIterator};
use std::rc::Rc;
use std::sync::{Arc, MutexGuard, RwLockWriteGuard};

use argon2::{self, Config};
use once_cell::sync::Lazy;
use rand::{RngCore, thread_rng};
use std::ops::Deref;
use crate::db_service::redis::RedisDataSource;
use std::net::ToSocketAddrs;
use r2d2_redis::RedisConnectionManager;
use r2d2::Pool;
use serde::{Serialize, Deserialize};
use oxide_auth::primitives::registrar::{PasswordPolicy, EncodedClient, Argon2, RegistrarError, Client, BoundClient, Registrar, RegisteredClient};

/// a db client service which implemented Registrar.
/// db: DataSource stored clients
/// password_policy: to encode client_secret.
pub struct Oauth2ClientService{
    pub db: RegistrarDataSource,
    password_policy: Option<Box<dyn PasswordPolicy>>,
}

/// A datasource service to restore clients;
/// users can change to another database like mysql or postgresql.
pub type RegistrarDataSource = RedisDataSource;

/// methods to search and regist clients from DataSource.
/// which should be implemented for all RegistrarDataSource.
pub trait OauthClientDBRepository {

    fn list(&self, salt: String) -> anyhow::Result<Vec<EncodedClient>>;

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient>;

    fn regist_from_encoded_client(&self, client: EncodedClient)  -> anyhow::Result<()>;

}


// this will be needed when you have features of different RegistrarDataSource
// impl OauthClientDBRepository for RegistrarDataSource{
//     fn list(&self, salt: String) -> anyhow::Result<Vec<EncodedClient>> {
//         (**self).list(salt)
//     }
//
//     fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient> {
//         (**self).find_client_by_id(id)
//     }
//
//     fn regist_from_encoded_client(&self, client: EncodedClient) -> anyhow::Result<()> {
//         (**self).regist_from_encoded_client(client)
//     }
//
// }


///////////////////////////////////////////////////////////////////////////////////////////////////
//                             Standard Implementations of Registrars                            //
///////////////////////////////////////////////////////////////////////////////////////////////////

static DEFAULT_PASSWORD_POLICY: Lazy<Argon2> = Lazy::new(|| { Argon2::default() });

impl Oauth2ClientService {
    /// Create an DB connection recording to features.
    pub fn new() -> Self {
        Oauth2ClientService{
            db: RegistrarDataSource::new(),
            password_policy: None
        }
    }

    /// Insert or update the client record.
    pub fn register_client(&mut self, client: Client) -> Result<(), RegistrarError>  {
        let password_policy = Self::current_policy(&self.password_policy);
        let encoded_client = client.encode(password_policy);

        self.db.regist_from_encoded_client(encoded_client)
            .map_err(|e| RegistrarError::Unspecified)
    }

    /// Change how passwords are encoded while stored.
    pub fn set_password_policy<P: PasswordPolicy + 'static>(&mut self, new_policy: P) {
        self.password_policy = Some(Box::new(new_policy))
    }

    // This is not an instance method because it needs to borrow the box but register needs &mut
    fn current_policy<'a>(policy: &'a Option<Box<dyn PasswordPolicy>>) -> &'a dyn PasswordPolicy {
        policy
            .as_ref().map(|boxed| &**boxed)
            .unwrap_or(&*DEFAULT_PASSWORD_POLICY)
    }
}


impl Extend<Client> for Oauth2ClientService {
    fn extend<I>(&mut self, iter: I) where I: IntoIterator<Item=Client> {
        iter.into_iter().for_each(|client| {
           self.register_client(client);
        })
    }
}

impl FromIterator<Client> for Oauth2ClientService {
    fn from_iter<I>(iter: I) -> Self where I: IntoIterator<Item=Client> {
        let mut into = Oauth2ClientService::new();
        into.extend(iter);
        into
    }
}

impl Registrar for Oauth2ClientService {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = match self.db.find_client_by_id(bound.client_id.as_ref()){
            Ok(detail) => detail,
            _ => return Err(RegistrarError::Unspecified)
        };
        // Perform exact matching as motivated in the rfc
        match bound.redirect_uri {
            None => (),
            Some(ref url) if url.as_ref().as_str() == client.redirect_uri.as_str() || client.additional_redirect_uris.contains(url) => (),
            _ => return Err(RegistrarError::Unspecified),
        }
        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: bound.redirect_uri.unwrap_or_else(
                || Cow::Owned(client.redirect_uri.clone())),
        })
    }

    /// Always overrides the scope with a default scope.
    fn negotiate<'a>(&self, bound: BoundClient<'a>, _scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        let client = self.db.find_client_by_id(&bound.client_id)
            .map_err(|e| RegistrarError::Unspecified)
            .unwrap();
        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: client.default_scope,
        })
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let password_policy = Self::current_policy(&self.password_policy);

        let client = self.db.find_client_by_id(client_id)
            .map_err(|e| RegistrarError::Unspecified);
        client.and_then(|op_client| {
            RegisteredClient::new(&op_client, password_policy)
                .check_authentication(passphrase)
        })?;

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_client() {
        let policy = Argon2::default();
        let client = Client::public(
            "ClientId",
            "https://example.com".parse().unwrap(),
            "default".parse().unwrap(),
        )
            .encode(&policy);
        let client = RegisteredClient::new(&client, &policy);

        // Providing no authentication data is ok
        assert!(client.check_authentication(None).is_ok());
        // Any authentication data is a fail
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn confidential_client() {
        let policy = Argon2::default();
        let pass = b"AB3fAj6GJpdxmEVeNCyPoA==";
        let client = Client::confidential(
            "ClientId",
            "https://example.com".parse().unwrap(),
            "default".parse().unwrap(),
            pass,
        )
            .encode(&policy);
        let client = RegisteredClient::new(&client, &policy);
        assert!(client.check_authentication(None).is_err());
        assert!(client.check_authentication(Some(pass)).is_ok());
        assert!(client.check_authentication(Some(b"not the passphrase")).is_err());
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn with_additional_redirect_uris() {
        let client_id = "ClientId";
        let redirect_uri: Url = "https://example.com/foo".parse().unwrap();
        let additional_redirect_uris: Vec<Url> = vec!["https://example.com/bar".parse().unwrap()];
        let default_scope = "default-scope".parse().unwrap();
        let client = Client::public(client_id, redirect_uri, default_scope)
            .with_additional_redirect_uris(additional_redirect_uris);
        let mut client_map = Oauth2ClientService::new();
        client_map.register_client(client);

        assert_eq!(
            client_map
                .bound_redirect(ClientUrl {
                    client_id: Cow::from(client_id),
                    redirect_uri: Some(Cow::Borrowed(&"https://example.com/foo".parse().unwrap()))
                })
                .unwrap()
                .redirect_uri,
            Cow::Owned("https://example.com/foo".parse().unwrap())
        );

        assert_eq!(
            client_map
                .bound_redirect(ClientUrl {
                    client_id: Cow::from(client_id),
                    redirect_uri: Some(Cow::Borrowed(&"https://example.com/bar".parse().unwrap()))
                })
                .unwrap()
                .redirect_uri,
            Cow::Owned("https://example.com/bar".parse().unwrap())
        );

        assert!(client_map
            .bound_redirect(ClientUrl {
                client_id: Cow::from(client_id),
                redirect_uri: Some(Cow::Borrowed(&"https://example.com/baz".parse().unwrap()))
            })
            .is_err());
    }

    #[test]
    fn client_service(){
        let mut oauth_service = Oauth2ClientService::new();
        let public_id = "PrivateClientId";
        let client_url = "https://example.com";

        let private_id = "PublicClientId";
        let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";

        let public_client =
            Client::public(public_id, client_url.parse().unwrap(), "default".parse().unwrap());

        println!("test register_client");

        oauth_service.register_client(public_client);
        oauth_service
            .check(public_id, None)
            .expect("Authorization of public client has changed");
        oauth_service
            .check(public_id, Some(b""))
            .err()
            .expect("Authorization with password succeeded");

        let private_client = Client::confidential(
            private_id,
            client_url.parse().unwrap(),
            "default".parse().unwrap(),
            private_passphrase,
        );


        oauth_service.register_client(private_client);

        oauth_service
            .check(private_id, Some(private_passphrase))
            .expect("Authorization with right password did not succeed");
        oauth_service
            .check(private_id, Some(b"Not the private passphrase"))
            .err()
            .expect("Authorization succeed with wrong password");
    }
}
