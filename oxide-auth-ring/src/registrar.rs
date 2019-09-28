use oxide_auth::primitives::registrar::{PasswordPolicy, RegistrarError};
use ring::{digest, pbkdf2, rand::{SystemRandom, SecureRandom}};
use std::{num::NonZeroU32, fmt};

/// Store passwords using `Pbkdf2` to derive the stored value.
///
/// Each instantiation generates a 16 byte random salt and prepends this additionally with the
/// username. This combined string is then used as the salt using the passphrase as the secret to
/// derive the output. The iteration count defaults to `65536` but can be customized.
pub struct Pbkdf2 {
    /// A prebuilt random, or constructing one as needed.
    random: Option<SystemRandom>,
    iterations: NonZeroU32,
}

impl Default for Pbkdf2 {
    fn default() -> Self {
        Pbkdf2 {
            random: Some(SystemRandom::new()),
            .. *PBKDF2_DEFAULTS
        }
    }
}

impl Clone for Pbkdf2 {
    fn clone(&self) -> Self {
        Pbkdf2 {
            random: Some(SystemRandom::new()),
            .. *self
        }
    }
}

impl fmt::Debug for Pbkdf2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Pbkdf2")
            .field("iterations", &self.iterations)
            .field("random", &())
            .finish()
    }
}

impl Pbkdf2 {
    /// Set the iteration count to `(1 << strength)`.
    ///
    /// This function will panic when the `strength` is larger or equal to `32`.
    pub fn set_relative_strength(&mut self, strength: u8) {
        assert!(strength < 32, "Strength value out of range (0-31): {}", strength);
        self.iterations = NonZeroU32::new(1u32 << strength).unwrap();
    }

    fn salt(&self, user_identifier: &[u8]) -> Vec<u8> {
        let mut vec = Vec::with_capacity(user_identifier.len() + 64);
        let mut rnd_salt = [0; 16];

        match self.random.as_ref() {
            Some(random) => random.fill(&mut rnd_salt),
            None => SystemRandom::new().fill(&mut rnd_salt),
        }.expect("Failed to property initialize password storage salt");

        vec.extend_from_slice(user_identifier);
        vec.extend_from_slice(&rnd_salt[..]);
        vec
    }
}

// A default instance for pbkdf2, randomness is sampled from the system each time.
//
// TODO: in the future there might be a way to get static memory initialized with an rng at load
// time by the loader. Then, a constant instance of the random generator may be available and we
// could get rid of the `Option`.
static PBKDF2_DEFAULTS: &Pbkdf2 = &Pbkdf2 {
    random: None,
    iterations: unsafe { NonZeroU32::new_unchecked(1 << 16) },
};

impl PasswordPolicy for Pbkdf2 {
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8> {
        let mut output = vec![0; 64];
        output.append(&mut self.salt(client_id.as_bytes()));
        {
            let (output, salt) = output.split_at_mut(64);
            pbkdf2::derive(&digest::SHA256, self.iterations.into(), salt, passphrase,
                output);
        }
        output
    }

    fn check(&self, _client_id: &str /* Was interned */, passphrase: &[u8], stored: &[u8])
        -> Result<(), RegistrarError>
    {
        if stored.len() < 64 {
            return Err(RegistrarError::Unspecified);
        }

        let (verifier, salt) = stored.split_at(64);
        pbkdf2::verify(&digest::SHA256, self.iterations.into(), salt, passphrase, verifier)
            .map_err(|_| RegistrarError::Unspecified)
    }
}

#[cfg(test)]
mod tests {
    use oxide_auth::primitives::registrar::{Client, RegisteredClient, Registrar, ClientMap};
    use super::*;

    /// A test suite for registrars which support simple registrations of arbitrary clients
    pub fn simple_test_suite<Reg, RegFn>(registrar: &mut Reg, register: RegFn)
    where
        Reg: Registrar,
        RegFn: Fn(&mut Reg, Client) -> Result<(), ()>
    {
        let public_id = "PrivateClientId";
        let client_url = "https://example.com";

        let private_id = "PublicClientId";
        let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";

        let public_client = Client::public(public_id, client_url.parse().unwrap(),
            "default".parse().unwrap());

        register(registrar, public_client).unwrap();

        {
            registrar.check(public_id, None)
                .expect("Authorization of public client has changed");
            registrar.check(public_id, Some(b""))
                .err().expect("Authorization with password succeeded");
        }

        let private_client = Client::confidential(private_id, client_url.parse().unwrap(),
            "default".parse().unwrap(), private_passphrase);

        register(registrar, private_client).unwrap();

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
}
