use std::str;
use nom::*;

use rfc5234::wsp;
use util::*;

pub struct XforwardParam(pub &'static str, pub Option<String>);


named!(command<CBS, &'static str>,
     alt!(
         map!(tag_no_case!("addr"), |_| "addr") |
         map!(tag_no_case!("helo"), |_| "helo") |
         map!(tag_no_case!("ident"), |_| "ident") |
         map!(tag_no_case!("name"), |_| "name") |
         map!(tag_no_case!("port"), |_| "port") |
         map!(tag_no_case!("proto"), |_| "proto") |
         map!(tag_no_case!("source"), |_| "source")
     )
);

named!(hexpair<CBS, u8>,
    map_res!(take_while_m_n!(2, 2, is_hex_digit),
             |x: CBS| u8::from_str_radix(str::from_utf8(x.0).unwrap(), 16))
);

named!(hexchar<CBS, u8>,
    do_parse!(
        tag!("+") >>
        a: hexpair >>
        (a)
    )
);

named!(xchar<CBS, CBS>,
       take_while1!(|c: u8| (33..=42).contains(&c) || (44..=60).contains(&c) || (62..=126).contains(&c))
);

named!(xtext<CBS, Vec<u8>>,
    fold_many0!(alt!(
        map!(xchar, |x| x.0.to_vec()) |
        map!(hexchar, |x| vec![x])), Vec::new(), |mut acc: Vec<_>, x| {acc.extend(x); acc} )
);

named!(unavailable<CBS, Option<String>>,
    map!(tag_no_case!("[unavailable]"), |_| None)
);

named!(value<CBS, Option<String>>,
    alt!(unavailable |
         map!(xtext, |x| Some(ascii_to_string(&x))))
);

named!(param<CBS, XforwardParam>,
    do_parse!(
        c: command >>
        tag!("=") >>
        v: value >>
        (XforwardParam(c, v))
    )
);

named!(params<CBS, Vec<XforwardParam>>,
    map!(pair!(
        do_parse!(
            opt!(many1!(wsp)) >>
            p: param >>
            (p)
        ),
        many1!(do_parse!(
            many1!(wsp) >>
                p: param >>
                (p)
        ))), |(a, b)| { let mut out = Vec::with_capacity(b.len()+1); out.push(a); out.extend(b); out }
    )
);

pub fn xforward_params(i: &[u8]) -> KResult<&[u8], Vec<XforwardParam>> {
    wrap_cbs_result(params(CBS(i)))
}
