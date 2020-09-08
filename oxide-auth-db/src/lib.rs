extern crate argon2;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate url;
extern crate r2d2_redis;
extern crate r2d2;
extern crate reqwest;
extern crate dotenv;

pub mod primitives;
pub mod db_service;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
