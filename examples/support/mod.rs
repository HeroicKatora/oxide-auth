//! Helper methods for several examples.
//!
//! These include a client instance for several implemented frontends. These are not part of the
//! main example code as this library focusses purely on the server side.
//!
//! On supported systems (which have the `x-www-browser` command), there is a utility to open
//! a page in the browser.
#![allow(unused)]

#[cfg(feature = "iron-frontend")]
pub mod iron;
#[cfg(feature = "rouille-frontend")]
pub mod rouille;
#[cfg(feature = "actix-frontend")]
pub mod actix;
#[cfg(feature = "rocket-frontend")]
pub mod rocket;

use oxide_auth::code_grant::endpoint::PreGrant;

/// Try to open the server url `http://localhost:8020` in the browser, or print a guiding statement
/// to the console if this is not possible.
pub fn open_in_browser() {
    use std::io::{Error, ErrorKind};
    use std::process::Command;

    let target_addres = "http://localhost:8020/";
    let open_with = if cfg!(target_os = "linux") {
        Ok("x-www-browser")
    } else {
        Err(Error::new(ErrorKind::Other, "Open not supported"))
    };

    open_with.and_then(|cmd| Command::new(cmd).arg(target_addres).status())
        .and_then(|status| if status.success() {
            Ok(())
        } else { 
            Err(Error::new(ErrorKind::Other, "Non zero status")) 
        })
        .unwrap_or_else(|_| println!("Please navigate to {}", target_addres));
}

pub fn consent_page_html(route: &str, grant: &PreGrant) -> String {
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?response_type=code&client_id={3:}\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?response_type=code&client_id={3:}&deny=1\">
</form>
</html>"
        };
    }
    
    format!(template!(), 
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        grant.client_id,
        &route)
}
