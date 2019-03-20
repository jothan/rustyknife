//! Robust parser for extracting a header section from a mail message
//!
//! Headers must be separated by CRLF. Loosely based on [RFC 5322] but
//! tolerates bytes above 127. The header section is considered to be
//! everything above a double CRLF.
//!
//! [RFC 5322]: https://tools.ietf.org/html/rfc5322

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

named!(field_name<CBS, CBS>,
       take_while1!(|c: u8| (33..=57).contains(&c) || (59..=126).contains(&c))
);

named!(unstructured<CBS, CBS>,
    recognize!(do_parse!(
        many0!(do_parse!(ofws >> alt!(recognize!(many1!(vchar)) | take_until1!("\r\n")) >> ())) >>
        many0!(wsp) >> ()
    ))
);

named!(optional_field<CBS, HeaderField>,
    do_parse!(
        name: field_name >>
        tag!(":") >>
        value: unstructured >>
        crlf >>
        (Ok((name.0, value.0)))
    )
);

// Extension to be able to walk through crap.
named!(invalid_field<CBS, HeaderField>,
    do_parse!(
        i: take_until1!("\r\n") >>
        crlf >>
        (Err(i.0))
    )
);

named!(fields<CBS, Vec<HeaderField>>,
    do_parse!(
        f: many0!(alt!(optional_field | invalid_field)) >>
        opt!(crlf) >>
        (f)
    )
);

/// Zero copy mail message header splitter
///
/// Returns the remaining input (the message body) and a vector of
/// [HeaderField] on success.
pub fn header_section(i: &[u8]) -> KResult<&[u8], Vec<HeaderField>> {
    wrap_cbs_result(fields(CBS(i)))
}
