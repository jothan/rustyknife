use std::env;
use std::os::unix::ffi::OsStrExt;

use rustyknife::rfc5321::command;

fn main() -> Result<(), String> {
    // Interpret each separate argument as a line ending in CRLF.
    let input : Vec<u8> = env::args_os().skip(1).fold(Vec::new(), |mut acc, x| {
        acc.extend(x.as_bytes());
        acc.extend(b"\r\n");
        acc
    });

    println!("input: {:?}\n", String::from_utf8_lossy(&input));

    let mut rem : &[u8] = &input;
    while !rem.is_empty() {
        let (res, parsed) = command(rem).map_err(|e| format!("{:?}", e))?;

        rem = res;
        println!("{:?}", parsed);
        println!("remainder: {:?}\n", String::from_utf8_lossy(rem));
    }


    Ok(())
}
