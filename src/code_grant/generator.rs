use super::{Grant, TokenGenerator};
use rand::{thread_rng, Rng};
use base64::{encode};

pub struct RandomGenerator {
    len: usize
}

impl RandomGenerator {
    pub fn new(length: usize) -> RandomGenerator {
        RandomGenerator {len: length}
    }
}

impl TokenGenerator for RandomGenerator {
    fn generate(&self, _grant: Grant) -> String {
        let result = thread_rng().gen_iter::<u8>().take(self.len).collect::<Vec<u8>>();
        encode(&result)
    }
}
