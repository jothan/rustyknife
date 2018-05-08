//! Postfix XFORWARD SMTP extension

use nom::*;

use rfc5234::wsp;
use rfc3461::xtext;
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
        many0!(do_parse!(
            many1!(wsp) >>
                p: param >>
                (p)
        ))), |(a, b)| { let mut out = Vec::with_capacity(b.len()+1); out.push(a); out.extend(b); out }
    )
);

pub fn xforward_params(i: &[u8]) -> KResult<&[u8], Vec<XforwardParam>> {
    wrap_cbs_result(params(CBS(i)))
}
