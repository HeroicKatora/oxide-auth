//! Helper methods for several examples.
//!
//! The support files for each frontend include a client instance for several implemented
//! frontends. These are not part of the main example code as this library focusses purely on the
//! server side. This module contains code that can be shared between the different frontends.
//! Since we want to be able to run the actix example but share it with rocket examples but
//! rocket includes macros in its crate root, the module include order is a bit strange.
//!
//! On supported systems (which have the `x-www-browser` command), there is a utility to open
//! a page in the browser.
#![allow(unused)]

/// Simplistic reqwest client.
#[path="./client.rs"]
mod client;

use oxide_auth::endpoint::Solicitation;
use std::fmt;

pub use self::client::{Client, Config as ClientConfig, Error as ClientError};

/// Try to open the server url `http://localhost:8020` in the browser, or print a guiding statement
/// to the console if this is not possible.
pub fn open_in_browser() {
    use std::io::{Error, ErrorKind};
    use std::process::Command;

    let target_addres = "http://localhost:8020/";

    // As suggested by <https://stackoverflow.com/questions/3739327/launching-a-website-via-windows-commandline>
    let open_with = if cfg!(target_os = "linux") {
        // `xdg-open` chosen over `x-www-browser` due to problems with the latter (#25)
        Ok("xdg-open")
    } else if cfg!(target_os = "windows") {
        Ok("explorer")
    } else if cfg!(target_os = "macos") {
        Ok("open")
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

pub fn consent_page_html(route: &str, solicitation: Solicitation) -> String {
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{5:}?response_type=code&client_id={3:}{4:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{5:}?response_type=code&client_id={3:}{4:}&deny=true\">
</form>
</html>"
        };
    }

    let grant = solicitation.pre_grant();
    let state = solicitation.state();
    
    format!(template!(), 
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        grant.client_id,
        if let Some(state) = state { format!("&state={}", state) } else { String::new() },
        &route)
}
