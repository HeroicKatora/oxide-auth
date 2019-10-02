extern crate oxide_auth;
extern crate oxide_auth_ring;

use oxide_auth::primitives::registrar::*;

use oxide_auth_ring::registrar::Pbkdf2;

/// A test suite for registrars which support simple registrations of arbitrary clients
pub fn simple_test_suite<Reg, RegFn>(registrar: &mut Reg, register: RegFn)
where
    Reg: Registrar,
    RegFn: Fn(&mut Reg, Client)
{
    let public_id = "PrivateClientId";
    let client_url = "https://example.com";

    let private_id = "PublicClientId";
    let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";

    let public_client = Client::public(public_id, client_url.parse().unwrap(),
        "default".parse().unwrap());

    register(registrar, public_client);

    {
        registrar.check(public_id, None)
            .expect("Authorization of public client has changed");
        registrar.check(public_id, Some(b""))
            .err().expect("Authorization with password succeeded");
    }

    let private_client = Client::confidential(private_id, client_url.parse().unwrap(),
        "default".parse().unwrap(), private_passphrase);

    register(registrar, private_client);

    {
        registrar.check(private_id, Some(private_passphrase))
            .expect("Authorization with right password did not succeed");
        registrar.check(private_id, Some(b"Not the private passphrase"))
            .err().expect("Authorization succeed with wrong password");
    }
}

#[test]
fn public_client() {
    let policy = Pbkdf2::default();
    let client = Client::public(
        "ClientId",
        "https://example.com".parse().unwrap(),
        "default".parse().unwrap()
    ).encode(&policy);
    let client = RegisteredClient::new(&client, &policy);

    // Providing no authentication data is ok
    assert!(client.check_authentication(None).is_ok());
    // Any authentication data is a fail
    assert!(client.check_authentication(Some(b"")).is_err());
}

#[test]
fn confidential_client() {
    let policy = Pbkdf2::default();
    let pass = b"AB3fAj6GJpdxmEVeNCyPoA==";
    let client = Client::confidential(
        "ClientId",
        "https://example.com".parse().unwrap(),
        "default".parse().unwrap(),
        pass
    ).encode(&policy);
    let client = RegisteredClient::new(&client, &policy);
    assert!(client.check_authentication(None).is_err());
    assert!(client.check_authentication(Some(pass)).is_ok());
    assert!(client.check_authentication(Some(b"not the passphrase")).is_err());
    assert!(client.check_authentication(Some(b"")).is_err());
}

#[test]
fn client_map() {
    let mut client_map = ClientMap::new();
    client_map.set_password_policy(Pbkdf2::default());
    simple_test_suite(&mut client_map, ClientMap::register_client);
}
