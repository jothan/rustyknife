//! Postfix [XFORWARD] SMTP extension parser
//!
//! [XFORWARD]: http://www.postfix.org/XFORWARD_README.html

use nom::*;
use nom::multi::{many0, many1};
use nom::combinator::{opt, map};
use nom::sequence::{pair, preceded};

use crate::rfc5234::wsp;
use crate::rfc3461::xtext;
use crate::util::*;

/// XFORWARD parameter name and value.
///
/// `"[UNAVAILABLE]"` is represented with a value of `None`.
pub struct Param(pub &'static str, pub Option<String>);

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
    alt!(unavailable | do_parse!(x: xtext >> (Some(ascii_to_string_vec(x)))))
);

named!(param<CBS, Param>,
    do_parse!(
        c: command >>
        tag!("=") >>
        v: value >>
        (Param(c, v))
    )
);

/// Parse a XFORWARD b`"attr1=value attr2=value"` string.
///
/// Returns a vector of [`Param`].
///
/// The parameter names must be valid and are normalized to
/// lowercase. The values are xtext decoded and a value of
/// `[UNAVAILABLE]` is translated to `None`. No other validation is
/// done.
pub fn xforward_params(input: &[u8]) -> NomResult<Vec<Param>> {
    map(pair(preceded(opt(many1(wsp)), param),
             many0(preceded(many1(wsp), param))),
        |(prefix, mut params)| {
            params.insert(0, prefix);
            params
        })(input)
}
