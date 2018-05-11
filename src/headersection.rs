//! Robust parser for extracting a header section from a mail message.
//!
//! Headers must be separated by CRLF. Loosely based on RFC5322 but
//! tolerates bytes above 127. The header section is considered to be
//! everything above a double CRLF.

use util::*;
use rfc5234::*;
use rfc5322::ofws;

pub enum HeaderField<'a> {
    /// Header name and value of a valid header.
    Valid(&'a[u8], &'a[u8]),

    /// Header part that does not contain a colon or contains 8bit
    /// bytes on the left hand side of the colon.
    Invalid(&'a[u8])
}

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
        (HeaderField::Valid(name.0, value.0))
    )
);

// Extension to be able to walk through crap.
named!(invalid_field<CBS, HeaderField>,
    do_parse!(
        i: take_until1!("\r\n") >>
        crlf >>
        (HeaderField::Invalid(i.0))
    )
);

named!(fields<CBS, Vec<HeaderField>>,
    do_parse!(
        f: many0!(alt!(optional_field | invalid_field)) >>
        opt!(crlf) >>
        (f)
    )
);

pub fn header_section(i: &[u8]) -> KResult<&[u8], Vec<HeaderField>> {
    wrap_cbs_result(fields(CBS(i)))
}
