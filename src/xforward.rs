//! Postfix XFORWARD SMTP extension

use nom::*;

use crate::rfc5234::wsp;
use crate::rfc3461::xtext;
use crate::util::*;

pub struct XforwardParam(pub &'static str, pub Option<String>);


named!(command<CBS, &'static str>,
     alt!(
         do_parse!(tag_no_case!("addr") >> ("addr")) |
         do_parse!(tag_no_case!("helo") >> ("helo")) |
         do_parse!(tag_no_case!("ident") >> ("ident")) |
         do_parse!(tag_no_case!("name") >> ("name")) |
         do_parse!(tag_no_case!("port") >> ("port")) |
         do_parse!(tag_no_case!("proto") >> ("proto")) |
         do_parse!(tag_no_case!("source") >> ("source"))
     )
);

named!(unavailable<CBS, Option<String>>,
    do_parse!(tag_no_case!("[unavailable]") >> (None))
);

named!(value<CBS, Option<String>>,
    alt!(unavailable | do_parse!(x: xtext >> (Some(ascii_to_string(x)))))
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
    do_parse!(
        a: do_parse!(
            opt!(many1!(wsp)) >>
            p: param >>
            (p)
        ) >>
        b: fold_many0!(do_parse!(
            many1!(wsp) >>
            p: param >>
            (p)
        ), vec![a], |mut acc: Vec<_>, item| {acc.push(item); acc}) >>
        (b)
    )
);

pub fn xforward_params(i: &[u8]) -> KResult<&[u8], Vec<XforwardParam>> {
    wrap_cbs_result(params(CBS(i)))
}
