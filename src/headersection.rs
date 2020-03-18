//! Robust parser for extracting a header section from a mail message
//!
//! Headers must be separated by CRLF. Loosely based on [RFC 5322] but
//! tolerates bytes above 127. The header section is considered to be
//! everything above a double CRLF.
//!
//! [RFC 5322]: https://tools.ietf.org/html/rfc5322

use std::borrow::Cow;
use std::str;

use nom::branch::alt;
use nom::bytes::streaming::{tag, take_while1, take_until};
use nom::combinator::{opt, map, map_opt, recognize};
use nom::multi::{many0, many1};
use nom::sequence::{pair, terminated, separated_pair};

use crate::util::*;

fn fws(input: &[u8]) -> NomResult<Cow<str>> {
    //CRLF is "semantically invisible"
    map(pair(opt(terminated(recognize_many0(wsp), crlf)),
             recognize_many1(wsp)),
        |(a, b)| {
            match a {
                Some(a) => {
                    let mut out = String::from(str::from_utf8(a).unwrap());
                    out.push_str(str::from_utf8(b).unwrap());
                    Cow::from(out)
                },
                None => Cow::from(str::from_utf8(b).unwrap())
            }
        })(input)
}

fn ofws(input: &[u8]) -> NomResult<Cow<str>> {
    map(opt(fws), |i| i.unwrap_or_else(|| Cow::from("")))(input)
}

fn sp(input: &[u8]) -> NomResult<&[u8]> {
    tag(" ")(input)
}

fn htab(input: &[u8]) -> NomResult<&[u8]> {
    tag("\t")(input)
}

fn wsp(input: &[u8]) -> NomResult<u8> {
    map(alt((sp, htab)), |x| x[0])(input)
}

fn vchar(input: &[u8]) -> NomResult<char> {
    map(take1_filter(|c| (0x21..=0x7e).contains(&c)), char::from)(input)
}

fn crlf(input: &[u8]) -> NomResult<&[u8]> {
    tag("\r\n")(input)
}

/// Used to represent a split header.
///
/// - The [`Ok`] variant is used when a valid header with a name was
/// found. This variant contains a tuple with the header name and
/// value.
/// - The [`Err`] variant is returned when the the first line of a header
/// does not contain a colon or contains 8bit bytes on the left hand
/// side of the colon.
pub type HeaderField<'a> = Result<(&'a[u8], &'a[u8]), &'a[u8]>;

fn field_name(input: &[u8]) -> NomResult<&[u8]> {
    take_while1(|c| match c {33..=57 | 59..=126 => true, _ => false})(input)
}

fn until_crlf(input: &[u8]) -> NomResult<&[u8]> {
    map_opt(take_until("\r\n"),
            |i: &[u8]| if !i.is_empty() {
                Some(i)
            } else {
                None
            })(input)
}

fn unstructured(input: &[u8]) -> NomResult<&[u8]> {
    recognize(pair(
        many0(pair(ofws, alt((recognize(many1(vchar)), until_crlf)))),
        many0(wsp)))(input)
}

fn field(input: &[u8]) -> NomResult<HeaderField> {
    map(terminated(separated_pair(field_name, tag(":"), unstructured), crlf), Ok)(input)
}

// Extension to be able to walk through crap.
fn invalid_field(input: &[u8]) -> NomResult<HeaderField> {
    map(terminated(until_crlf, crlf), Err)(input)
}

/// Zero copy mail message header splitter
///
/// Returns the remaining input (the message body) and a vector of
/// [HeaderField] on success.
pub fn header_section(input: &[u8]) -> NomResult<Vec<HeaderField>> {
    terminated(many0(alt((field, invalid_field))),
               opt(crlf))(input)
}

/// Parse a single header
pub fn header(input: &[u8]) -> NomResult<Option<HeaderField>> {
    alt((map(alt((field, invalid_field)), Some),
         map(crlf, |_| None)))(input)
}
