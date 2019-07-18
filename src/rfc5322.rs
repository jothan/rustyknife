//! Parsers for [Internet Message Format] messages.
//!
//! Comments are ignored. [RFC 2047] decoding is applied where appropriate.
//!
//! [Internet Message Format]: https://tools.ietf.org/html/rfc5322
//! [RFC 2047]: https://tools.ietf.org/html/rfc2047

use std::str;
use std::mem;

use nom::bytes::complete::tag;
use nom::multi::{fold_many0, many0, many1};
use nom::combinator::{map, opt};
use nom::sequence::{delimited, pair, preceded, terminated};

use crate::rfc2047::{_internal_encoded_word as encoded_word};
use crate::rfc5234::*;
use crate::types::{self, *};
use crate::util::*;

named!(quoted_pair<CBS, CBS>,
       do_parse!(
           tag!("\\") >>
           v: recognize!(alt!(vchar | wsp)) >> (v)
       )
);

named!(ctext<CBS, CBS>,
       take_while1!(|c: u8| (33..=39).contains(&c) || (42..=91).contains(&c) || (93..=126).contains(&c))
);

#[derive(Clone, Debug)]
enum CommentContent {
    Text(Vec<u8>),
    Comment(Vec<CommentContent>),
}

named!(ccontent<CBS, CommentContent>,
       alt!(map!(alt!(ctext | quoted_pair), |x| CommentContent::Text(x.to_vec())) | map!(comment, CommentContent::Comment))
);

fn fws(input: &[u8]) -> NomResult<Vec<u8>> {
    //CRLF is "semantically invisible"
    map(pair(opt(terminated(many0(wsp), crlf)),
             many1(wsp)),
        |(a, b)| {
            match a {
                Some(mut a) => { a.extend(b); a },
                None => b,
            }
        })(input)
}

named!(pub(crate) ofws<CBS, Vec<u8>>,
       map!(opt!(fws), |i| i.unwrap_or_default())
);

fn _concat_comment(comments: Vec<CommentContent>, extra: Option<CommentContent>) -> Vec<CommentContent> {
    let mut out = Vec::new();
    let mut acc_text = Vec::new();

    let push_text = |bytes: &mut Vec<_>, out: &mut Vec<CommentContent>| {
        if !bytes.is_empty() {
            out.push(CommentContent::Text(mem::replace(bytes, Vec::new())))
        }
    };

    for comment in comments.into_iter().chain(extra.into_iter()) {
        match comment {
            CommentContent::Text(mut text) => acc_text.append(&mut text),
            _ => { push_text(&mut acc_text, &mut out); out.push(comment) }
        }
    }
    push_text(&mut acc_text, &mut out);

    out
}

fn comment(input: &[u8]) -> NomResult<Vec<CommentContent>> {
    map(delimited(tag("("),
                  pair(fold_many0(pair(ofws, ccontent), Vec::new(), |mut acc, (fws, cc)| {
                      acc.push(CommentContent::Text(fws));
                      acc.push(cc);
                      acc
                  }), ofws),
                  tag(")")),
        |(a, b)| _concat_comment(a, Some(CommentContent::Text(b))))(input)
}

named!(cfws<CBS, CBS>,
    alt!(recognize!(pair!(many1!(pair!(ofws, comment)), ofws)) | recognize!(fws))
);

named!(qtext<CBS, CBS>,
    take_while1!(|c: u8| c == 33 || (35..=91).contains(&c) || (93..=126).contains(&c) || (128..=255).contains(&c))
);

#[cfg(feature = "quoted-string-rfc2047")]
named!(qcontent<CBS, QContent>,
    alt!(map!(encoded_word, QContent::EncodedWord) |
         map!(qtext, |x| QContent::Literal(ascii_to_string(x).into())) |
         map!(quoted_pair, |x| QContent::Literal(ascii_to_string(x).into()))
    )
);

#[cfg(not(feature = "quoted-string-rfc2047"))]
named!(qcontent<CBS, QContent>,
    alt!(map!(qtext, |x| QContent::Literal(ascii_to_string(x).into())) |
         map!(quoted_pair, |x| QContent::Literal(ascii_to_string(x).into()))
    )
);

// quoted-string not surrounded by CFWS
named!(_inner_quoted_string<CBS, Vec<QContent>>,
    do_parse!(
        tag!("\"") >>
        a: many0!(tuple!(opt!(fws), qcontent)) >>
        b: opt!(fws) >>
        tag!("\"") >>
        ({
            let mut out = Vec::with_capacity(a.len()*2+1);
            for (ws, cont) in a {
                match (ws, &cont, out.last()) {
                    #[cfg(feature = "quoted-string-rfc2047")]
                    (_, QContent::EncodedWord(_), Some(QContent::EncodedWord(_))) => (),
                    (Some(ws),_, _) => { out.push(QContent::Literal(ascii_to_string_vec(ws))); },
                    _ => (),
                }
                out.push(cont);
            }
            if let Some(x) = b { out.push(QContent::Literal(ascii_to_string_vec(x))) }
            out
        })
    )
);

named!(pub(crate) quoted_string<CBS, QuotedString>,
    do_parse!(
        opt!(cfws) >>
        qc: _inner_quoted_string >>
        opt!(cfws) >>
        (QuotedString(concat_qs(qc.into_iter())))
    )
);

/// A single mailbox with an optional display name.
#[derive(Clone, Debug, PartialEq)]
pub struct Mailbox {
    /// The display name.
    pub dname: Option<String>,
    /// The address of this mailbox.
    pub address: types::Mailbox,
}

/// A group of many [`Mailbox`].
#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    /// This group's display name.
    pub dname: String,
    /// The members of this group. May be empty.
    pub members: Vec<Mailbox>,
}

/// An address is either a single [`Mailbox`] or a [`Group`].
#[derive(Clone, Debug, PartialEq)]
pub enum Address {
    /// Single [`Mailbox`].
    Mailbox(Mailbox),
    /// [`Group`] of many [`Mailbox`].
    Group(Group),
}

#[derive(Clone, Debug)]
enum QContent {
    Literal(String),
    #[cfg(feature = "quoted-string-rfc2047")]
    EncodedWord(String),
}

#[derive(Clone, Debug)]
enum Text<'a> {
    Literal(String),
    Atom(&'a str),
}

impl <'a> From<&'a Text<'a>> for &'a str {
    fn from(t: &'a Text<'a>) -> &'a str {
        match t {
            Text::Literal(s) => s,
            Text::Atom(s) => s,
        }
    }
}

fn concat_qs<A: Iterator<Item=QContent>>(input: A) -> String {
    let mut out = String::new();

    for qc in input {
        match qc {
            QContent::Literal(lit) => out.push_str(&lit),
            #[cfg(feature = "quoted-string-rfc2047")]
            QContent::EncodedWord(ew) => out.push_str(&ew),
        }
    }
    out
}

named!(pub(crate) atext<CBS, CBS>,
    take_while1!(|c: u8| b"!#$%&'*+-/=?^_`{|}~".contains(&c) || (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c))
);

named!(pub(crate) dot_atom<CBS, DotAtom>,
    do_parse!(
        opt!(cfws) >>
        a: recognize!(pair!(atext, many0!(pair!(tag!("."), atext)))) >>
        opt!(cfws) >>
        (DotAtom(str::from_utf8(a).unwrap().into()))
    )
);

named!(pub(crate) atom<CBS, CBS>,
    do_parse!(
        opt!(cfws) >>
        a: atext >>
        opt!(cfws) >>
        (a)
    )
);

named!(_padded_encoded_word<CBS, String>,
    do_parse!(opt!(cfws) >> e: encoded_word >> opt!(cfws) >> (e))
);

named!(word<CBS, Text>,
    alt!(
        map!(_padded_encoded_word, Text::Literal) |
        map!(atom, |x| Text::Atom(str::from_utf8(&x).unwrap())) |
        map!(quoted_string, |qs| Text::Literal(qs.0))
    )
);

fn _concat_atom_and_qs<'a, A>(input: A) -> String
    where A: Iterator<Item=Text<'a>>,
{
    let mut iter = input.peekable();
    let mut out = String::new();

    while let Some(cur) = iter.next() {
        match (cur, iter.peek()) {
            (Text::Atom(v), Some(_)) => {out.push_str(&v); out.push(' ')},
            (_, Some(Text::Atom(v))) => {out.push_str(&v); out.push(' ')},
            (ref t1, _) => out.push_str(t1.into()),
        };
    };

    out
}

named!(display_name<CBS, String>,
    map!(many1!(word), |words| _concat_atom_and_qs(words.into_iter().map(Into::into)))
);

named!(pub(crate) local_part<CBS, LocalPart>,
    alt!(map!(dot_atom, |a| a.into()) |
         map!(quoted_string, LocalPart::Quoted))
);

named!(dtext<CBS, CBS>,
    take_while1!(|c: u8| (33..=90).contains(&c) || (94..=126).contains(&c))
);

named!(pub(crate) domain_literal<CBS, AddressLiteral>,
    do_parse!(
        opt!(cfws) >>
        tag!("[") >>
        a: many0!(tuple!(ofws, dtext)) >>
        b: ofws >>
        tag!("]") >>
        opt!(cfws) >>
        ({
            let mut out : Vec<u8> = a.iter().flat_map(|(x, y)| x.iter().chain(y.iter())).cloned().collect();
            out.extend_from_slice(&b);
            let literal = AddressLiteral::FreeForm(String::from_utf8(out).unwrap());
            literal.upgrade().unwrap_or(literal)
        })
    )
);

named!(pub(crate) _domain<CBS, Domain>,
    map!(dot_atom, |a| Domain(a.0))
);

named!(pub(crate) domain<CBS, DomainPart>,
    alt!(map!(_domain, DomainPart::Domain) | map!(domain_literal, DomainPart::Address))
);

named!(pub(crate) addr_spec<CBS, types::Mailbox>,
    do_parse!(
        lp: local_part >>
        tag!("@") >>
        domain: domain >>
        (types::Mailbox(lp, domain))
    )
);

named!(angle_addr<CBS, types::Mailbox>,
    do_parse!(
        opt!(cfws) >>
        tag!("<") >>
        address: addr_spec >>
        tag!(">") >>
        opt!(cfws) >>
        (address)
    )
);

named!(name_addr<CBS, Mailbox>,
    do_parse!(
        dname: opt!(display_name) >>
        address: angle_addr >>
        (Mailbox{dname, address})
    )
);

named!(mailbox<CBS, Mailbox>,
    alt!(name_addr | map!(addr_spec, |a| Mailbox{dname: None, address: a}))
);

pub fn mailbox_list(input: &[u8]) -> NomResult<Vec<Mailbox>> {
    map(pair(mailbox,
             many0(preceded(tag(","), mailbox))),
        |(prefix, mut mbx)| {
            mbx.insert(0, prefix);
            mbx
        }
    )(input)
}

named!(group_list<CBS, Vec<Mailbox>>,
    alt!(mailbox_list | map!(cfws, |_| vec![]))
);

named!(group<CBS, Group>,
    do_parse!(
        dname: display_name >>
        tag!(":") >>
        members: opt!(group_list) >>
        tag!(";") >>
        opt!(cfws) >>
        (Group{dname, members: members.unwrap_or_default()})
    )
);

named!(address<CBS, Address>,
    alt!(map!(mailbox, Address::Mailbox) | map!(group, Address::Group))
);

fn address_list(input: &[u8]) -> NomResult<Vec<Address>> {
    map(pair(address,
             many0(preceded(tag(","), address))),
        |(prefix, mut list)| {
            list.insert(0, prefix);
            list
        }
    )(input)
}

named!(address_list_crlf<CBS, Vec<Address>>,
    do_parse!(
        a: address_list >>
        opt!(crlf) >>
        (a)
    )
);

named!(address_crlf<CBS, Address>,
    do_parse!(
        a: address >>
        opt!(crlf) >>
        (a)
    )
);

#[inline]
named!(_8bit_char<CBS, u8>,
       map!(verify!(take!(1), |c: CBS| (0x80..=0xff).contains(&c[0])), |x| x[0])
);

named!(_unstructured<CBS, String>,
    do_parse!(
        a: many0!(alt!(
            do_parse!(
                ws: opt!(fws) >>
                ew: encoded_word >>
                ewcont: many0!(do_parse!(fws >> e: encoded_word >> (Text::Literal(e)))) >>
                ({
                    let mut out = Vec::with_capacity(ewcont.len()+2);
                    if let Some(x) = ws { out.push(Text::Literal(ascii_to_string_vec(x))) };
                    out.push(Text::Literal(ew));
                    out.extend_from_slice(&ewcont);
                    out
                })
            ) |
            do_parse!(
                ws: opt!(fws) >>
                vc: many1!(alt!(vchar | _8bit_char)) >>
                ({
                    let mut out = Vec::new();
                    if let Some(x) = ws {
                        out.extend_from_slice(&x)
                    };
                    out.extend_from_slice(&vc);
                    vec![Text::Literal(ascii_to_string_vec(out))]
                })
            )

        )) >>
        b: many0!(wsp) >>
        ({
            let iter =  a.into_iter().flat_map(IntoIterator::into_iter).chain(std::iter::once(Text::Literal(ascii_to_string_vec(b))));
            _concat_atom_and_qs(iter)
        })
    )
);

/// Parse the content of a `"From:"` header.
///
/// Returns a list of addresses, since [RFC 6854] allows multiple mail
/// authors.
///
/// [RFC 6854]: https://tools.ietf.org/html/rfc6854
pub fn from(i: &[u8]) -> KResult<&[u8], Vec<Address>> {
    address_list_crlf(i)
}

/// Parse the content of a `"Sender:"` header.
///
/// Returns a single address.
pub fn sender(i: &[u8]) -> KResult<&[u8], Address> {
    address_crlf(i)
}

/// Parse the content of a `"Reply-To:"` header.
///
/// Returns a list of addresses.
pub fn reply_to(i: &[u8]) -> KResult<&[u8], Vec<Address>> {
    address_list_crlf(i)
}

/// Parse an unstructured header such as `"Subject:"`.
///
/// Returns a fully decoded string.
pub fn unstructured(i: &[u8]) -> KResult<&[u8], String> {
    _unstructured(i)
}
