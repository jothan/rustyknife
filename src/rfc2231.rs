//! [Encoded MIME parameters]
//!
//! Implements [RFC 2045] syntax extended with RFC 2231
//!
//! [Encoded MIME parameters]: https://tools.ietf.org/html/rfc2231
//! [RFC 2045]: https://tools.ietf.org/html/rfc2045


use std::borrow::Cow;
use std::fmt::{self, Display};
use std::str;
use std::collections::HashMap;

use charset::decode_ascii;

use encoding_rs::Encoding;
use encoding_rs::UTF_8; // TODO: was ASCII

use nom::branch::alt;
use nom::bytes::complete::{tag, tag_no_case, take_while1, take_while_m_n};
use nom::character::is_digit;
use nom::combinator::{map, opt, recognize, verify};
use nom::multi::many0;
use nom::sequence::{delimited, pair, preceded, separated_pair, terminated, tuple};

use crate::util::*;
use crate::rfc3461::hexpair;
use crate::rfc5234::crlf;
use crate::rfc5322::{ofws, quoted_string};

#[derive(Debug)]
struct Parameter<'a> {
    name: Name<'a>,
    value: Value<'a>,
}

#[derive(Debug)]
struct Name<'a> {
    section: Option<u32>,
    name: &'a str,
}

#[derive(Debug)]
enum Value<'a> {
    Regular(Cow<'a, str>),
    Extended(ExtendedValue<'a>),
}

#[derive(Debug)]
enum ExtendedValue<'a> {
    Initial { encoding: Option<&'a [u8]>, language: Option<&'a [u8]>, value: Vec<u8> },
    Other(Vec<u8>),
}

fn _equals(input: &[u8]) -> NomResult<()> {
    map(tuple((ofws, tag("="), ofws)), |_| ())(input)
}

fn parameter(input: &[u8]) -> NomResult<Parameter> {
    alt((regular_parameter, extended_parameter))(input)
}

fn regular_parameter(input: &[u8]) -> NomResult<Parameter> {
    map(separated_pair(regular_parameter_name, _equals, value),
        |(name, value)| Parameter{name, value: Value::Regular(value)})(input)
}

fn regular_parameter_name(input: &[u8]) -> NomResult<Name> {
    map(pair(attribute, opt(section)),
        |(name, section)| Name{name: std::str::from_utf8(name).unwrap(), section}
    )(input)
}

fn token(input: &[u8]) -> NomResult<&str> {
    map(take_while1(|c| (33..=126).contains(&c) && !b"()<>@,;:\\\"/[]?=".contains(&c)),
        |t| std::str::from_utf8(t).unwrap())(input)
}

fn is_attribute_char(c: u8) -> bool {
    (33..=126).contains(&c) && !b"*'%()<>@,;:\\\"/[]?=".contains(&c)
}

fn attribute_char(input: &[u8]) -> NomResult<u8> {
    take1_filter(is_attribute_char)(input)
}

fn attribute(input: &[u8]) -> NomResult<&[u8]> {
    take_while1(is_attribute_char)(input)
}

fn section(input: &[u8]) -> NomResult<u32> {
    alt((initial_section, other_sections))(input)
}

fn initial_section(input: &[u8]) -> NomResult<u32> {
    map(tag("*0"), |_| 0)(input)
}

fn other_sections(input: &[u8]) -> NomResult<u32> {
    map(preceded(tag("*"), verify(take_while_m_n(1, 8, is_digit), |x: &[u8]| x[0] != b'0')),
        |s| str::from_utf8(s).unwrap().parse().unwrap())(input)
}

fn extended_parameter(input: &[u8]) -> NomResult<Parameter> {
    alt((
        map(separated_pair(extended_initial_name,
                           _equals,
                           extended_initial_value),
            |(name, value)| Parameter{name, value: Value::Extended(value)}),

        map(separated_pair(extended_other_names,
                           _equals,
                           extended_other_values),
            |(name, value)| Parameter{name, value: Value::Extended(ExtendedValue::Other(value))}),
   ))(input)
}

fn extended_initial_name(input: &[u8]) -> NomResult<Name> {
    map(terminated(pair(attribute, opt(initial_section)), tag("*")),
        |(name, section)| Name{name: str::from_utf8(&name).unwrap(), section})(input)
}

fn extended_other_names(input: &[u8]) -> NomResult<Name> {
    map(terminated(pair(attribute, other_sections), tag("*")),
        |(name, section)| Name{name: str::from_utf8(&name).unwrap(), section: Some(section)})(input)
}

fn extended_initial_value(input: &[u8]) -> NomResult<ExtendedValue> {
    map(tuple((terminated(opt(attribute), tag("'")),
               terminated(opt(attribute), tag("'")),
               extended_other_values)),
        |(encoding, language, value)| ExtendedValue::Initial{encoding, language, value})(input)
}

fn ext_octet(input: &[u8]) -> NomResult<u8> {
    preceded(tag("%"), hexpair)(input)
}

fn extended_other_values(input: &[u8]) -> NomResult<Vec<u8>> {
    many0(alt((ext_octet, attribute_char)))(input)
}

fn value(input: &[u8]) -> NomResult<Cow<str>> {
    alt((map(token, Cow::from),
         map(quoted_string::<crate::behaviour::Intl>, |qs| Cow::from(qs.0))))(input)
}

fn _mime_type(input: &[u8]) -> NomResult<&[u8]> {
    recognize(tuple((token, tag("/"), token)))(input)
}

fn _parameter_list(input: &[u8]) -> NomResult<Vec<Parameter>> {
    terminated(many0(preceded(pair(tag(";"), ofws), parameter)),
               pair(opt(tag(";")), opt(crlf)))(input)
}

#[derive(Debug)]
enum Segment<'a> {
    Encoded(Vec<u8>),
    Decoded(Cow<'a, str>),
}

fn decode_segments(mut input: Vec<(u32, Segment)>, encoding: &'static Encoding) -> String {
    input.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    let mut encoded = Vec::new();

    let decode = |bytes: &mut Vec<_>, out: &mut String| {
        out.push_str(&encoding.decode_without_bom_handling(&bytes).0);
        bytes.clear();
    };

    // Clump encoded segments together before decoding. Prevents partial UTF-8 sequences or similar with other encodings.
    for (_, segment) in input {
        match segment {
            Segment::Encoded(mut bytes) => encoded.append(&mut bytes),
            Segment::Decoded(s) => { decode(&mut encoded, &mut out); out.push_str(&s) }
        }
    }
    decode(&mut encoded, &mut out);

    out
}

fn decode_parameter_list(input: Vec<Parameter>) -> Vec<(String, String)> {
    let mut simple = HashMap::<String, String>::new();
    let mut simple_encoded = HashMap::<String, String>::new();
    let mut composite = HashMap::<String, Vec<(u32, Segment)>>::new();
    let mut composite_encoding = HashMap::new();

    for Parameter{name, value} in input {
        let name_norm = name.name.to_lowercase();

        match name.section {
            None => {
                match value {
                    Value::Regular(v) => { simple.insert(name_norm, v.into()); },
                    Value::Extended(ExtendedValue::Initial{value, encoding: encoding_name, ..}) => {
                        let codec = match encoding_name {
                            Some(encoding_name) => Encoding::for_label(&decode_ascii(encoding_name).as_bytes()).unwrap_or(UTF_8),
                            None => UTF_8,
                        };
                        simple_encoded.insert(name_norm, codec.decode_without_bom_handling(value.as_slice()).0.to_string()); // TODO: eliminate to_string
                    }
                    Value::Extended(ExtendedValue::Other(..)) => unreachable!(),
                }
            },
            Some(section) => {
                let ent = composite.entry(name_norm.clone()).or_default();

                match value {
                    Value::Regular(v) => ent.push((section, Segment::Decoded(v))),
                    Value::Extended(ExtendedValue::Initial{value, encoding: encoding_name, ..}) => {
                        if let Some(encoding_name) = encoding_name {
                            if let Some(codec) = Encoding::for_label(&decode_ascii(encoding_name).as_bytes()) {
                                composite_encoding.insert(name_norm, codec);
                            }
                        }
                        ent.push((section, Segment::Encoded(value.to_vec())))
                    }
                    Value::Extended(ExtendedValue::Other(v)) => ent.push((section, Segment::Encoded(v))),
                }
            }
        }
    }

    let mut composite_out = Vec::new();
    for (name, segments) in composite {
        let codec = composite_encoding.get(&name).cloned().unwrap_or(UTF_8);
        composite_out.push((name, decode_segments(segments, codec)));
    }

    for (name, value) in simple_encoded.into_iter().chain(composite_out.into_iter()) {
        simple.insert(name, value);
    }

    simple.into_iter().collect()
}

/// Parse a MIME `"Content-Type"` header.
///
/// Returns a tuple of the MIME type and parameters.
pub fn content_type(input: &[u8]) -> NomResult<(String, Vec<(String, String)>)> {
    map(pair(delimited(ofws, _mime_type, ofws),
             _parameter_list),
        |(mt, p)| (decode_ascii(mt).to_lowercase(), decode_parameter_list(p)))(input)
}

fn _x_token(input: &[u8]) -> NomResult<&str> {
    preceded(tag_no_case("x-"), token)(input)
}

/// Value from a MIME `"Content-Disposition"` header.
#[derive(Debug, PartialEq)]
pub enum ContentDisposition {
    /// "inline"
    Inline,
    /// "attachment"
    Attachment,
    /// Value prefixed with "X-". The prefix is not stored in the
    /// string.
    Extended(String),
    /// Any syntaxically valid token that is not any known disposition.
    Token(String),
}

impl Display for ContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ContentDisposition::Inline => write!(f, "inline"),
            ContentDisposition::Attachment => write!(f, "attachment"),
            ContentDisposition::Extended(s) => write!(f, "x-{}", s),
            ContentDisposition::Token(t) => write!(f, "{}", t),
        }
    }
}

fn _disposition(input: &[u8]) -> NomResult<ContentDisposition> {
    alt((
        map(tag_no_case("inline"), |_| ContentDisposition::Inline),
        map(tag_no_case("attachment"), |_| ContentDisposition::Attachment),
        map(_x_token, |x| ContentDisposition::Extended(x.into())),
        map(token, |t| ContentDisposition::Token(t.into()))
    ))(input)
}

/// Parse a MIME `"Content-Disposition"` header.
///
/// Returns a tuple of [`ContentDisposition`] and parameters.
pub fn content_disposition(input: &[u8]) -> NomResult<(ContentDisposition, Vec<(String, String)>)> {
    map(pair(delimited(ofws, _disposition, ofws),
             _parameter_list),
        |(disp, p)| (disp, decode_parameter_list(p)))(input)
}

/// Value from a MIME `"Content-Transfer-Encoding"` header.
#[derive(Debug, PartialEq)]
pub enum ContentTransferEncoding {
    /// "7bit"
    SevenBit,
    /// "8bit"
    EightBit,
    /// "binary"
    Binary,
    /// "base64"
    Base64,
    /// "quoted-printable"
    QuotedPrintable,
    /// Value prefixed with "X-". The prefix is not stored in the
    /// string.
    Extended(String),
    /// Any syntaxically valid token that is not any known encoding.
    Token(String),
}

impl Display for ContentTransferEncoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CTE::SevenBit => write!(f, "7bit"),
            CTE::EightBit => write!(f, "8bit"),
            CTE::Binary => write!(f, "binary"),
            CTE::Base64 => write!(f, "base64"),
            CTE::QuotedPrintable => write!(f, "quoted-printable"),
            CTE::Extended(s) => write!(f, "x-{}", s),
            CTE::Token(t) => write!(f, "{}", t),
        }
    }
}

use self::ContentTransferEncoding as CTE;

/// Parse a MIME `"Content-Transfer-Encoding"` header.
///
/// Returns a [`ContentTransferEncoding`].
pub fn content_transfer_encoding(input: &[u8]) -> NomResult<ContentTransferEncoding> {
    delimited(ofws, alt((
        map(tag_no_case("7bit"), |_| CTE::SevenBit),
        map(tag_no_case("8bit"), |_| CTE::EightBit),
        map(tag_no_case("binary"), |_| CTE::Binary),
        map(tag_no_case("base64"), |_| CTE::Base64),
        map(tag_no_case("quoted-printable"), |_| CTE::QuotedPrintable),
        map(_x_token, |x| CTE::Extended(x.into())),
        map(token, |t| CTE::Token(t.into()))
    )), ofws)(input)
}
