//! Encoded MIME parameters
//!
//! Implements RFC 2045 syntax extended with RFC 2231

use std::str;
use std::collections::HashMap;

use encoding::label::encoding_from_whatwg_label;
use encoding::types::EncodingRef;
use encoding::DecoderTrap;
use encoding::all::ASCII;
use nom::is_digit;

use crate::util::*;
use crate::rfc3461::hexpair;
use crate::rfc5234::crlf;
use crate::rfc5322::{ofws, quoted_string};

#[derive(Debug)]
struct Parameter<'a> {
    name: Name,
    value: Value<'a>,
}

#[derive(Debug)]
struct Name {
    section: Option<u32>,
    name: String,
}

#[derive(Debug)]
enum Value<'a> {
    Regular(String),
    Extended(ExtendedValue<'a>),
}

#[derive(Debug)]
enum ExtendedValue<'a> {
    Initial { encoding: Option<&'a [u8]>, language: Option<&'a [u8]>, value: Vec<u8> },
    Other(Vec<u8>),
}

named!(_equals<CBS, ()>,
    do_parse!(
        ofws >>
        tag!("=") >>
        ofws >>
        ()
    )
);

named!(parameter<CBS, Parameter>,
    alt!(regular_parameter | extended_parameter)
);

named!(regular_parameter<CBS, Parameter>,
    do_parse!(
        name: regular_parameter_name >>
        _equals >>
        value: value >>
        (Parameter{name, value: Value::Regular(value)})
    )
);

named!(regular_parameter_name<CBS, Name>,
    do_parse!(
        name: attribute >>
        section: opt!(section) >>
        (Name{name: ascii_to_string(name), section})
    )
);

named!(token<CBS, CBS>,
    take_while1!(|c| (33..=126).contains(&c) && !b"()<>@,;:\\\"/[]?=".contains(&c))
);

fn is_attribute_char(c: u8) -> bool {
    (33..=126).contains(&c) && !b"*'%()<>@,;:\\\"/[]?=".contains(&c)
}

#[inline]
named!(attribute_char<CBS, u8>,
    map!(verify!(take!(1), |x: CBS| is_attribute_char(x.0[0])), |c| c[0])
);

named!(attribute<CBS, CBS>,
    take_while1!(|c| is_attribute_char(c))
);

named!(section<CBS, u32>,
    alt!(initial_section | other_sections)
);

named!(initial_section<CBS, u32>,
    do_parse!(tag!("*0") >> (0))
);

named!(other_sections<CBS, u32>,
    do_parse!(
        tag!("*") >>
        s: verify!(take_while_m_n!(1, 9, is_digit), |x: CBS| x.0[0] != b'0') >>
        (str::from_utf8(&s).unwrap().parse().unwrap())
    )
);

named!(extended_parameter<CBS, Parameter>,
   alt!(
       do_parse!(
           name: extended_initial_name >>
           _equals >>
           value: extended_initial_value >>
           (Parameter{name, value: Value::Extended(value)})
       ) |
       do_parse!(
           name: extended_other_names >>
           _equals >>
           value: extended_other_values >>
           (Parameter{name, value: Value::Extended(ExtendedValue::Other(value))})
       )
   )
);

named!(extended_initial_name<CBS, Name>,
    do_parse!(
        name: attribute >>
        section: opt!(initial_section) >>
        tag!("*") >>
        (Name{name: ascii_to_string(name), section})
    )
);

named!(extended_other_names<CBS, Name>,
    do_parse!(
        name: attribute >>
        section: other_sections >>
        tag!("*") >>
        (Name{name: ascii_to_string(name), section: Some(section)})
    )
);

named!(extended_initial_value<CBS, ExtendedValue>,
    do_parse!(
        e: opt!(attribute) >>
        tag!("'") >>
        l: opt!(attribute) >>
        tag!("'") >>
        v: extended_other_values >>
        (ExtendedValue::Initial{encoding: e.map(|x| x.0), language: l.map(|x| x.0), value: v})
    )
);

named!(ext_octet<CBS, u8>,
    do_parse!(tag!("%") >> h: hexpair >> (h))
);

named!(extended_other_values<CBS, Vec<u8>>,
    many0!(alt!(ext_octet | attribute_char))
);

named!(value<CBS, String>,
   alt!(map!(token, |x| ascii_to_string(x)) | quoted_string)
);


named!(_mime_type<CBS, CBS>,
    recognize!(do_parse!(token >> tag!("/") >> token >> ()))
);

named!(_parameter_list<CBS, Vec<Parameter>>,
    do_parse!(
        p: many0!(do_parse!(tag!(";") >> ofws >> p: parameter >> (p))) >>
        opt!(tag!(";")) >>
        opt!(crlf) >>
        (p)
    )
);

#[derive(Debug)]
enum Segment {
    Encoded(Vec<u8>),
    Decoded(String),
}

fn decode_segments(mut input: Vec<(u32, Segment)>, encoding: EncodingRef) -> String {
    input.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    let mut encoded = Vec::new();

    let decode = |bytes: &mut Vec<_>, out: &mut String| {
        out.push_str(&encoding.decode(&bytes, DecoderTrap::Replace).unwrap());
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
                    Value::Regular(v) => { simple.insert(name_norm, v); },
                    Value::Extended(ExtendedValue::Initial{value, encoding: encoding_name, ..}) => {
                        let codec = match encoding_name {
                            Some(encoding_name) => encoding_from_whatwg_label(&ascii_to_string(&encoding_name)).unwrap_or(ASCII),
                            None => ASCII,
                        };
                        simple_encoded.insert(name_norm, codec.decode(&value, DecoderTrap::Replace).unwrap());
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
                            if let Some(codec) = encoding_from_whatwg_label(&ascii_to_string(&encoding_name)) {
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
        let codec = composite_encoding.get(&name).cloned().unwrap_or(ASCII);
        composite_out.push((name, decode_segments(segments, codec)));
    }

    for (name, value) in simple_encoded.into_iter().chain(composite_out.into_iter()) {
        simple.insert(name, value);
    }

    simple.into_iter().collect()
}

named!(_content_type<CBS, (String, Vec<(String, String)>)>,
    do_parse!(
        ofws >>
        mt: _mime_type >>
        ofws >>
        p: _parameter_list >>
        (ascii_to_string(mt).to_lowercase(), decode_parameter_list(p))
    )
);


named!(_x_token<CBS, String>,
    map!(recognize!(do_parse!(
        tag_no_case!("x-") >>
        token >>
        ()
    )), |x| ascii_to_string(x))
);

named!(_disposition<CBS, String>,
    alt!(
        map!(tag_no_case!("inline"), |_| String::from("inline")) |
        map!(tag_no_case!("attachment"), |_| String::from("attachment")) |
        map!(_x_token, |x| x.to_lowercase())
    )
);

named!(_content_disposition<CBS, (String, Vec<(String, String)>)>,
    do_parse!(
        ofws >>
        disp: _disposition >>
        ofws >>
        p: _parameter_list >>
        (disp, decode_parameter_list(p))
    )
);

named!(_content_transfer_encoding<CBS, String>,
    do_parse!(
        ofws >>
        cte: alt!(
            map!(tag_no_case!("7bit"), |_| String::from("7bit")) |
            map!(tag_no_case!("8bit"), |_| String::from("8bit")) |
            map!(tag_no_case!("binary"), |_| String::from("binary")) |
            map!(tag_no_case!("base64"), |_| String::from("base64")) |
            map!(tag_no_case!("quoted-printable"), |_| String::from("quoted-printable")) |
            map!(_x_token, |x| x.to_lowercase())
        ) >>
        ofws >>
        (cte)
    )
);

pub fn content_type(i: &[u8]) -> KResult<&[u8], (String, Vec<(String, String)>)> {
    wrap_cbs_result(_content_type(CBS(i)))
}

pub fn content_disposition(i: &[u8]) -> KResult<&[u8], (String, Vec<(String, String)>)> {
    wrap_cbs_result(_content_disposition(CBS(i)))
}

pub fn content_transfer_encoding(i: &[u8]) -> KResult<&[u8], String> {
    // Strip CRLF manually, needed because of the bad interaction of
    // FWS with an optional CRLF.
    let s = if i.ends_with(b"\r\n") {
        &i[0..i.len()-2]
    } else {
        i
    };
    wrap_cbs_result(_content_transfer_encoding(CBS(s)))
}
