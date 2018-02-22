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

/// Try to open the server url `http://localhost:8020` in the browser, or print a guiding statement
/// to the console if this is not possible.
pub fn open_in_browser() {
    let target_addres = "http://localhost:8020/";
    use std::io::{Error, ErrorKind};
    use std::process::Command;
    let can_open = if cfg!(target_os = "linux") {
        Ok("x-www-browser")
    } else {
        Err(Error::new(ErrorKind::Other, "Open not supported"))
    };
    can_open.and_then(|cmd| Command::new(cmd).arg(target_addres).status())
        .and_then(|status| if status.success() { Ok(()) } else { Err(Error::new(ErrorKind::Other, "Non zero status")) })
        .unwrap_or_else(|_| println!("Please navigate to {}", target_addres));
}
