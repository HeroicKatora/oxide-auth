extern crate iron;
use self::iron::Url;

pub enum ClientType { Confidential, Public }
pub trait Client {
    fn client_type(&self) -> ClientType;
    fn client_identifier(&self) -> String;
    fn contains_redirect(&self, url: &Url) -> bool;
}
