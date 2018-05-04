//! Robust parser for extracting a header section from a mail message.
//!
//! Headers must be separated by CRLF. Loosely based on RFC5322 but
//! tolerates bytes above 127. The header section is considered to be
//! everything above a double CRLF.

use util::*;
use rfc5234::*;
use rfc5322::ofws;

pub enum HeaderField<'a> {
    Valid(&'a[u8], &'a[u8]),
    Invalid(&'a[u8])
}

named!(field_name<CBS, CBS>,
       take_while1!(|c: u8| (33..=57).contains(&c) || (59..=126).contains(&c))
);

named!(_8bitchar<CBS, CBS>,
    take_while1!(|c: u8| (128..=255).contains(&c))
);

named!(unstructured<CBS, CBS>,
    recognize!(pair!(
        many0!(pair!(ofws, alt!(vchar | take_until1!("\r\n")))),
        many0!(wsp)
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
#[allow(unused_imports)]
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
