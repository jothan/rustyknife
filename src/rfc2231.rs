//! Encoded MIME parameters
//!
//! Implements RFC 2045 syntax extended with RFC 2231

use std::str;
use std::collections::HashMap;

use encoding::label::encoding_from_whatwg_label;
use encoding::DecoderTrap;
use encoding::all::ASCII;
use nom::is_digit;

use util::*;
use rfc3461::hexpair;
use rfc5234::crlf;
use rfc5322::{ofws, quoted_string};

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
        (Name{name: ascii_to_string(name.0), section})
    )
);

named!(token<CBS, CBS>,
    take_while1!(|c| (33..=126).contains(&c) && !b"()<>@,;:\\\"/[]?=".contains(&c))
);

fn is_attribute_char(c: u8) -> bool {
    (33..=126).contains(&c) && !b"*'%()<>@,;:\\\"/[]?=".contains(&c)
}

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
        (Name{name: ascii_to_string(name.0), section})
    )
);

named!(extended_other_names<CBS, Name>,
    do_parse!(
        name: attribute >>
        section: other_sections >>
        tag!("*") >>
        (Name{name: ascii_to_string(name.0), section: Some(section)})
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
   alt!(map!(token, |x| ascii_to_string(&x.0)) | quoted_string)
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

#[derive(Clone, Debug)]
enum Segment<'a> {
    Encoded(Vec<u8>),
    Decoded(&'a str),
}

fn decode_parameter_list(input: &[Parameter]) -> Vec<(String, String)> {
    let mut simple = HashMap::<String, String>::new();
    let mut simple_encoded = HashMap::<String, String>::new();
    let mut composite = HashMap::<String, Vec<(u32, Segment)>>::new();

    let mut encmap = HashMap::new();
    for Parameter{name, value} in input {
        let name_norm = name.name.to_lowercase();

        match name.section {
            None => {
                match value {
                    Value::Regular(v) => { simple.insert(name_norm.clone(), v.clone()); },
                    Value::Extended(ExtendedValue::Initial{value, encoding, ..}) => {
                        let encoding = encoding_from_whatwg_label(&ascii_to_string(encoding.unwrap_or(b"ascii"))).unwrap_or(ASCII);
                        simple_encoded.insert(name_norm.clone(), encoding.decode(&value, DecoderTrap::Replace).unwrap());
                    }
                    Value::Extended(ExtendedValue::Other(..)) => unreachable!(),
                }
            },
            Some(section) => {
                let ent = composite.entry(name_norm.clone()).or_default();

                match value {
                    Value::Regular(v) => ent.push((section, Segment::Decoded(&v))),
                    Value::Extended(ExtendedValue::Initial{value, encoding, ..}) => {
                        if let Some(encoding) = encoding {
                            let encoding = encoding_from_whatwg_label(&ascii_to_string(encoding)).unwrap_or(ASCII);
                            encmap.insert(name_norm, encoding);
                        }
                        ent.push((section, Segment::Encoded(value.to_vec())))
                    }
                    Value::Extended(ExtendedValue::Other(v)) => ent.push((section, Segment::Encoded(v.to_vec()))),
                }
            }
        }
    }
    let mut composite_out = HashMap::<String, String>::new();

    // Clump encoded segments together before decoding. Prevents partial UTF-8 sequences or similar with other encodings.
    for (name, segments) in composite.iter_mut() {
        segments.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out_seg = Vec::new();
        for (_, segment) in segments {
            match segment {
                Segment::Encoded(s) => {
                    let modified = if let Some(Segment::Encoded(prev)) = out_seg.last_mut() {
                        prev.extend(s.iter());
                        true
                    } else {
                        false
                    };

                    if !modified {
                        out_seg.push(segment.clone());
                    }
                }
                Segment::Decoded(..) => out_seg.push(segment.clone()),
            }
        }
        let mut out_str = String::new();

        for segment in out_seg {
            match segment {
                Segment::Encoded(s) => {
                    let encoding = encmap.get(name).unwrap();
                    out_str.push_str(&encoding.decode(&s, DecoderTrap::Replace).unwrap())
                }
                Segment::Decoded(s) => out_str.push_str(s),
            }
        }
        composite_out.insert(name.clone(), out_str);
    }

    for (name, value) in simple_encoded.drain().chain(composite_out.drain()) {
        simple.insert(name, value);
    }

    simple.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

named!(_content_type<CBS, (String, Vec<(String, String)>)>,
    do_parse!(
        ofws >>
        mt: _mime_type >>
        ofws >>
        p: _parameter_list >>
        (ascii_to_string(mt.0).to_lowercase(), decode_parameter_list(&p))
    )
);


named!(_x_token<CBS, String>,
    map!(recognize!(do_parse!(
        tag_no_case!("x-") >>
        token >>
        ()
    )), |x| ascii_to_string(&x.0))
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
        (disp, decode_parameter_list(&p))
    )
);

named!(_content_transfer_encoding<CBS, String>,
    alt!(
        map!(tag_no_case!("7bit"), |_| String::from("7bit")) |
        map!(tag_no_case!("8bit"), |_| String::from("8bit")) |
        map!(tag_no_case!("binary"), |_| String::from("binary")) |
        map!(tag_no_case!("quoted-printable"), |_| String::from("quoted-printable")) |
        map!(_x_token, |x| x.to_lowercase())
    )
);

pub fn content_type(i: &[u8]) -> KResult<&[u8], (String, Vec<(String, String)>)> {
    wrap_cbs_result(_content_type(CBS(i)))
}

pub fn content_disposition(i: &[u8]) -> KResult<&[u8], (String, Vec<(String, String)>)> {
    wrap_cbs_result(_content_disposition(CBS(i)))
}

pub fn content_transfer_encoding(i: &[u8]) -> KResult<&[u8], String> {
    wrap_cbs_result(_content_transfer_encoding(CBS(i)))
}
