//! Robust parser for extracting a header section from a mail message
//!
//! Headers must be separated by CRLF. Loosely based on [RFC 5322] but
//! tolerates bytes above 127. The header section is considered to be
//! everything above a double CRLF.
//!
//! [RFC 5322]: https://tools.ietf.org/html/rfc5322

use nom::branch::alt;
use nom::multi::{many0, many1};
use nom::sequence::{pair, terminated, separated_pair};
use nom::bytes::complete::{tag, take_while1, take_until};
use nom::combinator::{opt, map, map_opt, recognize};

use crate::util::*;
use crate::rfc5234::*;
use crate::rfc5322::ofws;

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
    take_while1(|c: u8| (33..=57).contains(&c) || (59..=126).contains(&c))(input)
}

fn until_crlf<'a>(input: &'a [u8]) -> NomResult<'a, &'a [u8]> {
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

fn fields(input: &[u8]) -> NomResult<Vec<HeaderField>> {
    terminated(many0(alt((optional_field, invalid_field))),
               opt(crlf))(input)
}

fn optional_field(input: &[u8]) -> NomResult<HeaderField> {
    terminated(
        map(separated_pair(field_name, tag(":"), unstructured),
            |(name, value)| Ok((name, value))),
        crlf)(input)
}

// Extension to be able to walk through crap.
fn invalid_field(input: &[u8]) -> NomResult<HeaderField> {
    map(terminated(until_crlf, crlf),
        |v| Err(v))(input)
}

/// Zero copy mail message header splitter
///
/// Returns the remaining input (the message body) and a vector of
/// [HeaderField] on success.
pub fn header_section(input: &[u8]) -> NomResult<Vec<HeaderField>> {
    terminated(many0(alt((optional_field, invalid_field))),
               opt(crlf))(input)
}
