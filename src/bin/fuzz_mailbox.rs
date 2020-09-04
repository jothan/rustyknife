#[macro_use]
extern crate afl;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = rustyknife::rfc5321::mailbox::<rustyknife::behaviour::Intl>(data);
    });
}
