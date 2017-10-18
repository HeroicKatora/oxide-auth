use super::{Grant, TokenGenerator};
use rand::{thread_rng, Rng};

pub struct RandomGenerator {

}

impl TokenGenerator for RandomGenerator {
    fn generate(&self, _grant: Grant) -> String {
        let result = thread_rng().gen::<[u8; 16]>();
        "".to_string()
    }
}
