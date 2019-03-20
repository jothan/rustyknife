//! [Header extensions for non-ASCII text]
//!
//! [Header extensions for non-ASCII text]: https://tools.ietf.org/html/rfc2047


use std::borrow::Cow;

use base64;
use encoding::DecoderTrap;
use encoding::all::ASCII;
use encoding::label::encoding_from_whatwg_label;

use crate::util::*;
use crate::rfc3461::hexpair;

named!(token<CBS, CBS>,
    take_while1!(|c| (33..=126).contains(&c) && !b"()<>@,;:\\\"/[]?.=".contains(&c))
);

named!(encoded_text<CBS, CBS>,
    take_while1!(|c| (33..=62).contains(&c) || (64..=126).contains(&c))
);

#[inline]
named!(_qp_encoded_text<CBS, Vec<u8>>,
    many0!(alt!(
        do_parse!(tag!("=") >> b: hexpair >> (b)) |
        map!(tag!("_"), |_| b' ') |
        map!(take!(1), |x| x.0[0])
    ))
);

// Decode the modified quoted-printable as defined by this RFC.
fn decode_qp(input: &[u8]) -> Option<Vec<u8>>
{
    exact!(CBS(input), _qp_encoded_text).ok().map(|(_, o)| o)
}

// Undoes the quoted-printable or base64 encoding.
fn decode_text(encoding: &[u8], text: &[u8]) -> Option<Vec<u8>>
{
    match &encoding.to_ascii_lowercase()[..] {
        b"q" => decode_qp(text),
        b"b" => base64::decode(text).ok(),
        _ => None,
    }
}

// Encoded word with no charset decoding.
named!(_encoded_word<CBS, (Cow<'_, str>, Vec<u8>)>,
    do_parse!(
        tag!("=?") >>
        charset: token >>
        _lang: opt!(do_parse!(tag!("*") >> l: token >> (l))) >> // From RFC2231
        tag!("?") >>
        encoding: token >>
        tag!("?") >>
        encoded_text: encoded_text >>
        tag!("?=") >>
        (ascii_to_string(charset), decode_text(encoding.0, encoded_text.0).unwrap_or_else(|| encoded_text.0.to_vec()))
    )
);

fn decode_charset((charset, bytes): (Cow<'_, str>, Vec<u8>)) -> String
{
    encoding_from_whatwg_label(&charset).unwrap_or(ASCII).decode(&bytes, DecoderTrap::Replace).unwrap()
}

named!(pub encoded_word<CBS, String>,
    map!(_encoded_word, decode_charset)
);
