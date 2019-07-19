//! Postfix [XFORWARD] SMTP extension parser
//!
//! [XFORWARD]: http://www.postfix.org/XFORWARD_README.html

use nom::branch::alt;
use nom::bytes::complete::{tag, tag_no_case};
use nom::combinator::{opt, map};
use nom::multi::{many0, many1};
use nom::sequence::{pair, preceded, separated_pair};

use crate::rfc5234::wsp;
use crate::rfc3461::xtext;
use crate::util::*;

/// XFORWARD parameter name and value.
///
/// `"[UNAVAILABLE]"` is represented with a value of `None`.
pub struct Param(pub &'static str, pub Option<String>);

fn command(input: &[u8]) -> NomResult<&'static str> {
    alt((map(tag_no_case("addr"), |_| "addr"),
         map(tag_no_case("helo"), |_| "helo"),
         map(tag_no_case("ident"), |_| "ident"),
         map(tag_no_case("name"), |_| "name"),
         map(tag_no_case("port"), |_| "port"),
         map(tag_no_case("proto"), |_| "proto"),
         map(tag_no_case("source"), |_| "source")))(input)
}

fn unavailable(input: &[u8]) -> NomResult<Option<String>> {
    map(tag_no_case("[unavailable]"), |_| None)(input)
}

fn value(input: &[u8]) -> NomResult<Option<String>> {
    alt((unavailable, map(xtext, |x| Some(ascii_to_string_vec(x)))))(input)
}

fn param(input: &[u8]) -> NomResult<Param> {
    map(separated_pair(command, tag("="), value),
        |(c, v)| Param(c, v))(input)
}

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
