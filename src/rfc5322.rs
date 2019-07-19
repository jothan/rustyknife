//! Parsers for [Internet Message Format] messages.
//!
//! Comments are ignored. [RFC 2047] decoding is applied where appropriate.
//!
//! [Internet Message Format]: https://tools.ietf.org/html/rfc5322
//! [RFC 2047]: https://tools.ietf.org/html/rfc2047

use std::str;
use std::mem;

use nom::branch::alt;
use nom::bytes::complete::{tag, take, take_while1};
use nom::multi::{fold_many0, many0, many1};
use nom::combinator::{map, opt, recognize, verify};
use nom::sequence::{delimited, pair, preceded, separated_pair, terminated, tuple};

use crate::rfc2047::encoded_word;
use crate::rfc5234::*;
use crate::types::{self, *};
use crate::util::*;

fn quoted_pair(input: &[u8]) -> NomResult<&[u8]> {
    preceded(tag("\\"), recognize(alt((vchar, wsp))))(input)
}

fn ctext(input: &[u8]) -> NomResult<&[u8]> {
    take_while1(|c: u8| (33..=39).contains(&c) || (42..=91).contains(&c) || (93..=126).contains(&c))(input)
}

#[derive(Clone, Debug)]
enum CommentContent {
    Text(Vec<u8>),
    Comment(Vec<CommentContent>),
}

fn ccontent(input: &[u8]) -> NomResult<CommentContent> {
    alt((map(alt((ctext, quoted_pair)), |x| CommentContent::Text(x.to_vec())),
         map(comment, CommentContent::Comment)))(input)
}

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

pub(crate) fn ofws(input: &[u8]) -> NomResult<Vec<u8>> {
    map(opt(fws), |i| i.unwrap_or_default())(input)
}

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

fn cfws(input: &[u8]) -> NomResult<&[u8]> {
    alt((recognize(pair(many1(pair(ofws, comment)), ofws)), recognize(fws)))(input)
}

fn qtext(input: &[u8]) -> NomResult<&[u8]> {
    take_while1(|c: u8| c == 33 || (35..=91).contains(&c) || (93..=126).contains(&c) || (128..=255).contains(&c))(input)
}

#[cfg(feature = "quoted-string-rfc2047")]
fn qcontent(input: &[u8]) -> NomResult<QContent> {
    alt((map(encoded_word, QContent::EncodedWord),
         map(qtext, |x| QContent::Literal(ascii_to_string(x).into())),
         map(quoted_pair, |x| QContent::Literal(ascii_to_string(x).into())))
    )(input)
}

#[cfg(not(feature = "quoted-string-rfc2047"))]
fn qcontent(input: &[u8]) -> NomResult<QContent> {
    alt((map(qtext, |x| QContent::Literal(ascii_to_string(x).into())),
         map(quoted_pair, |x| QContent::Literal(ascii_to_string(x).into())))
    )(input)
}

// quoted-string not surrounded by CFWS
fn _inner_quoted_string(input: &[u8]) -> NomResult<Vec<QContent>> {
    map(delimited(tag("\""),
                  pair(many0(pair(opt(fws), qcontent)), opt(fws)),
                  tag("\"")),
        |(a, b)| {
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
        })(input)
}

pub(crate) fn quoted_string(input: &[u8]) -> NomResult<QuotedString> {
    map(delimited(opt(cfws), _inner_quoted_string, opt(cfws)),
        |qc| QuotedString(concat_qs(qc.into_iter())))(input)
}

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

pub(crate) fn atext(input: &[u8]) -> NomResult<&[u8]> {
    take_while1(|c: u8| b"!#$%&'*+-/=?^_`{|}~".contains(&c) || (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c))(input)
}

pub(crate) fn dot_atom(input: &[u8]) -> NomResult<DotAtom> {
    map(delimited(opt(cfws), recognize(pair(atext, many0(pair(tag("."), atext)))), opt(cfws)),
        |a| (DotAtom(str::from_utf8(a).unwrap().into())))(input)
}

pub(crate) fn atom(input: &[u8]) -> NomResult<&[u8]> {
    delimited(opt(cfws), atext, opt(cfws))(input)
}

pub(crate) fn _padded_encoded_word(input: &[u8]) -> NomResult<String> {
    delimited(opt(cfws), encoded_word, opt(cfws))(input)
}

fn word(input: &[u8]) -> NomResult<Text> {
    alt((
        map(_padded_encoded_word, Text::Literal),
        map(atom, |x| Text::Atom(str::from_utf8(&x).unwrap())),
        map(quoted_string, |qs| Text::Literal(qs.0))
    ))(input)
}

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

fn display_name(input: &[u8]) -> NomResult<String> {
    map(many1(word), |words| _concat_atom_and_qs(words.into_iter().map(Into::into)))(input)
}

pub(crate) fn local_part(input: &[u8]) -> NomResult<LocalPart> {
    alt((map(dot_atom, |a| a.into()),
         map(quoted_string, LocalPart::Quoted)))(input)
}

fn dtext(input: &[u8]) -> NomResult<&[u8]> {
    take_while1(|c: u8| (33..=90).contains(&c) || (94..=126).contains(&c))(input)
}

pub(crate) fn domain_literal(input: &[u8]) -> NomResult<AddressLiteral> {
    map(delimited(pair(opt(cfws), tag("[")),
                  pair(many0(pair(ofws, dtext)), ofws),
                  pair(tag("]"), opt(cfws))),
        |(a, b)| {
            let mut out : Vec<u8> = a.iter().flat_map(|(x, y)| x.iter().chain(y.iter())).cloned().collect();
            out.extend_from_slice(&b);
            let literal = AddressLiteral::FreeForm(String::from_utf8(out).unwrap());
            literal.upgrade().unwrap_or(literal)
        })(input)
}

pub(crate) fn _domain(input: &[u8]) -> NomResult<Domain> {
    map(dot_atom, |a| Domain(a.0))(input)
}

pub(crate) fn domain(input: &[u8]) -> NomResult<DomainPart> {
    alt((map(_domain, DomainPart::Domain),
         map(domain_literal, DomainPart::Address)))(input)
}

pub(crate) fn addr_spec(input: &[u8]) -> NomResult<types::Mailbox> {
    map(separated_pair(local_part, tag("@"), domain),
        |(lp, domain)| types::Mailbox(lp, domain))(input)
}

fn angle_addr(input: &[u8]) -> NomResult<types::Mailbox> {
    delimited(pair(opt(cfws), tag("<")),
              addr_spec,
              pair(tag(">"), opt(cfws)))(input)
}

fn name_addr(input: &[u8]) -> NomResult<Mailbox> {
    map(pair(opt(display_name), angle_addr),
        |(dname, address)| Mailbox{dname, address})(input)
}

fn mailbox(input: &[u8]) -> NomResult<Mailbox> {
    alt((name_addr,
         map(addr_spec, |a| Mailbox{dname: None, address: a})))(input)
}

fn mailbox_list(input: &[u8]) -> NomResult<Vec<Mailbox>> {
    map(pair(mailbox,
             many0(preceded(tag(","), mailbox))),
        |(prefix, mut mbx)| {
            mbx.insert(0, prefix);
            mbx
        }
    )(input)
}

fn group_list(input: &[u8]) -> NomResult<Vec<Mailbox>> {
    alt((mailbox_list, map(cfws, |_| vec![])))(input)
}

fn group(input: &[u8]) -> NomResult<Group> {
    map(pair(terminated(display_name, tag(":")),
             terminated(opt(group_list), pair(tag(";"), opt(cfws)))),
        |(dname, members)| Group{dname, members: members.unwrap_or_default()})(input)
}

fn address(input: &[u8]) -> NomResult<Address> {
    alt((map(mailbox, Address::Mailbox),
         map(group, Address::Group)))(input)
}

fn address_list(input: &[u8]) -> NomResult<Vec<Address>> {
    map(pair(address,
             many0(preceded(tag(","), address))),
        |(prefix, mut list)| {
            list.insert(0, prefix);
            list
        }
    )(input)
}

fn address_list_crlf(input: &[u8]) -> NomResult<Vec<Address>> {
    terminated(address_list, opt(crlf))(input)
}

fn address_crlf(input: &[u8]) -> NomResult<Address> {
    terminated(address, opt(crlf))(input)
}

fn _8bit_char(input: &[u8]) -> NomResult<u8> {
    map(verify(take(1usize), |c: &[u8]| (0x80..=0xff).contains(&c[0])), |x: &[u8]| x[0])(input)
}

/// Parse an unstructured header such as `"Subject:"`.
///
/// Returns a fully decoded string.
pub fn unstructured(input: &[u8]) -> NomResult<String> {
    map(pair(
        many0(alt((
            map(tuple((opt(fws), encoded_word, many0(map(preceded(fws, encoded_word), Text::Literal)))),
                |(ws, ew, ewcont)| {
                    let mut out = Vec::with_capacity(ewcont.len()+2);
                    if let Some(x) = ws { out.push(Text::Literal(ascii_to_string_vec(x))) };
                    out.push(Text::Literal(ew));
                    out.extend_from_slice(&ewcont);
                    out
                }),
            map(pair(opt(fws), many1(alt((vchar, _8bit_char)))),
                |(ws, vc)| {
                    let mut out = Vec::new();
                    if let Some(x) = ws {
                        out.extend_from_slice(&x)
                    };
                    out.extend_from_slice(&vc);
                    vec![Text::Literal(ascii_to_string_vec(out))]
                })))),
        many0(wsp)),
        |(a, b)| {
            let iter =  a.into_iter().flat_map(IntoIterator::into_iter).chain(std::iter::once(Text::Literal(ascii_to_string_vec(b))));
            _concat_atom_and_qs(iter)
        })(input)
}

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
