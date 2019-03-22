extern crate rustyknife;

use std::env;
use std::os::unix::ffi::OsStrExt;

use rustyknife::rfc5321::command;

fn main() -> Result<(), String> {
    // Interpret each separate argument as a line.
    let mut s : Vec<u8> = Vec::new();
    for x in env::args_os().skip(1) {
        s.extend(x.as_os_str().as_bytes().iter()); s.extend(b"\r\n");
    };
    println!("input: {:?}\n", String::from_utf8_lossy(&s));

    let mut rem : &[u8] = &s;
    while !rem.is_empty() {
        let (res, parsed) = command(rem).map_err(|e| e.to_string())?;

        rem = res;
        println!("{:?}", parsed);
        println!("remainder: {:?}\n", String::from_utf8_lossy(rem));
    }


    Ok(())
}
