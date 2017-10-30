extern crate base64;
extern crate chrono;
extern crate url;
extern crate rand;
extern crate ring;
extern crate rmp_serde;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

pub mod code_grant;
#[cfg(feature = "iron-backend")]
pub mod iron;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {

    }
}
