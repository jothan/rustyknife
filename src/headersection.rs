//! Robust parser for extracting a header section from a mail message
//!
//! Headers must be separated by CRLF. Loosely based on [RFC 5322] but
//! tolerates bytes above 127. The header section is considered to be
//! everything above a double CRLF.
//!
//! [RFC 5322]: https://tools.ietf.org/html/rfc5322

use nom::branch::alt;
use nom::multi::many0;
use nom::sequence::{terminated, separated_pair};
use nom::bytes::complete::{tag, take_while1, take_until};
use nom::combinator::{opt, map, map_opt};

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

named!(unstructured<CBS, CBS>,
    recognize!(do_parse!(
        many0!(do_parse!(ofws >> alt!(recognize!(many1!(vchar)) | take_until1!("\r\n")) >> ())) >>
        many0!(wsp) >> ()
    ))
);

named!(fields<CBS, Vec<HeaderField>>,
    do_parse!(
        f: many0!(alt!(optional_field | invalid_field)) >>
        opt!(crlf) >>
        (f)
    )
);

fn optional_field(input: &[u8]) -> NomResult<HeaderField> {
    terminated(
        map(separated_pair(field_name, tag(":"), unstructured),
            |(name, value)| Ok((name, value))),
        crlf)(input)
}

// Extension to be able to walk through crap.
fn invalid_field(input: &[u8]) -> NomResult<HeaderField> {
    map_opt(terminated(take_until("\r\n"), crlf),
            |i| if !i.is_empty() {
                Some(Err(i))
            } else {
                None
            }
    )(input)
}

/// Zero copy mail message header splitter
///
/// Returns the remaining input (the message body) and a vector of
/// [HeaderField] on success.
pub fn header_section(input: &[u8]) -> NomResult<Vec<HeaderField>> {
    terminated(many0(alt((optional_field, invalid_field))),
               opt(crlf))(input)
}
