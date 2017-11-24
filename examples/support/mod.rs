#[cfg(feature = "iron-backend")]
pub mod iron;

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
