use std::{fmt, num::NonZeroU32};
use ring::{rand::{SystemRandom, SecureRandom}, digest, pbkdf2};
use oxide_auth::primitives::registrar::{PasswordPolicy, RegistrarError};

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
            return Err(RegistrarError::PrimitiveError)
        }

        let (verifier, salt) = stored.split_at(64);
        pbkdf2::verify(&digest::SHA256, self.iterations.into(), salt, passphrase, verifier)
            .map_err(|_| RegistrarError::Unspecified)
    }
}

