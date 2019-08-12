extern crate rustyknife;

use std::env;
use std::os::unix::ffi::OsStringExt;

use rustyknife::behaviour::Intl;
use rustyknife::rfc5322::from;

fn main() {
    let args : Vec<_> = env::args_os().skip(1).map(|x| x.into_vec()).collect();
    let res = from::<Intl>(&args[0]);
    println!("{:?}", res);
    let (rem, parsed) = res.unwrap();

    println!("'{:?}'", parsed);
    println!("'{}'", String::from_utf8_lossy(rem));
}
