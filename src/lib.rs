extern crate base64;
extern crate chrono;
extern crate url;
extern crate rand;

pub mod code_grant;
#[cfg(feature = "iron-backend")]
pub mod iron;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {

    }
}
