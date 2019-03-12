//! Parsers for Internet Message Format messages.
//!
//! Comments are ignored. RFC2047 decoding is applied where appropriate.

use std::mem;
use std::iter;

use crate::rfc2047::encoded_word;
use crate::rfc5234::*;
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
       alt!(map!(alt!(ctext | quoted_pair), |x| CommentContent::Text(x.0.to_vec())) | map!(comment, CommentContent::Comment))
);

named!(fws<CBS, Vec<u8>>,
    do_parse!(
        a: opt!(do_parse!(
            w: many0!(wsp) >>
            crlf >> //CRLF is "semantically invisible"
            (w)
        )) >>
        b: many1!(wsp) >>
        ({
            let mut out = Vec::with_capacity(b.len());
            if let Some(x) = a { out.extend_from_slice(&x) };
            out.extend_from_slice(&b);
            out
        })
    )
);


named!(pub ofws<CBS, Vec<u8>>,
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

named!(comment<CBS, Vec<CommentContent>>,
    do_parse!(
        tag!("(") >>
        a: fold_many0!(tuple!(ofws, ccontent), Vec::new(), |mut acc: Vec<_>, (fws, cc)| {
            acc.push(CommentContent::Text(fws));
            acc.push(cc);
            acc
        }) >>
        b: ofws >>
        tag!(")") >>
        (_concat_comment(a, Some(CommentContent::Text(b))))
    )
);

named!(cfws<CBS, CBS>,
    alt!(recognize!(pair!(many1!(pair!(opt!(fws), comment)), opt!(fws))) | recognize!(fws))
);

named!(qtext<CBS, CBS>,
    take_while1!(|c: u8| c == 33 || (35..=91).contains(&c) || (93..=126).contains(&c) || (128..=255).contains(&c))
);

#[cfg(feature = "quoted-string-rfc2047")]
named!(qcontent<CBS, QContent>,
    alt!(map!(encoded_word, QContent::EncodedWord) |
         map!(qtext, |x| QContent::Literal(ascii_to_string_slice(x.0))) |
         map!(quoted_pair, |x| QContent::Literal(ascii_to_string_slice(x.0)))
    )
);

#[cfg(not(feature = "quoted-string-rfc2047"))]
named!(qcontent<CBS, QContent>,
    alt!(map!(qtext, |x| QContent::Literal(ascii_to_string_slice(x.0))) |
         map!(quoted_pair, |x| QContent::Literal(ascii_to_string_slice(x.0)))
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
                match (&cont, out.last()) {
                    #[cfg(feature = "quoted-string-rfc2047")]
                    (QContent::EncodedWord(_), Some(QContent::EncodedWord(_))) => (),
                    (_, _) => { if let Some(x) = ws { out.push(QContent::Literal(ascii_to_string(x))) } },
                }
                out.push(cont);
            }
            if let Some(x) = b { out.push(QContent::Literal(ascii_to_string(x))) }
            out
        })
    )
);

// Undecoded quoted-string
named!(_raw_quoted_string<CBS, CBS>,
    do_parse!(
        opt!(cfws) >>
        qc: recognize!(_inner_quoted_string) >>
        opt!(cfws) >>
        (qc)
    )
);

named!(_quoted_string_parts<CBS, Vec<QContent>>,
    do_parse!(
        opt!(cfws) >>
        qc: _inner_quoted_string >>
        opt!(cfws) >>
        (qc)
    )
);

named!(pub quoted_string<CBS, String>,
    do_parse!(qs: _quoted_string_parts >> (_concat_atom_and_qs(Word::QS(qs))))
);

#[derive(Clone, Debug, PartialEq)]
pub struct Mailbox {
    pub dname: Option<String>,
    pub address: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    pub dname: String,
    pub members: Vec<Mailbox>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Address {
    Mailbox(Mailbox),
    Group(Group),
}

#[derive(Clone, Debug)]
enum Word {
    EncodedWord(String),
    Atom(String),
    QS(Vec<QContent>),
}

#[derive(Clone, Debug)]
enum QContent {
    Literal(String),
    #[cfg(feature = "quoted-string-rfc2047")]
    EncodedWord(String),
}

#[derive(Clone, Debug)]
enum Text {
    Literal(String),
    Atom(String),
}

impl Text {
    fn get(&self) -> &str {
        match self {
            Text::Literal(s) => s,
            Text::Atom(s) => s,
        }
    }
}

trait IntoTextIter {
    fn iter_text(self) -> Box<dyn Iterator<Item=Text>>;
}

impl IntoTextIter for QContent {
    fn iter_text(self) -> Box<dyn Iterator<Item=Text>> {
        match self {
            QContent::Literal(lit) => Box::new(iter::once(Text::Literal(lit))),
            #[cfg(feature = "quoted-string-rfc2047")]
            QContent::EncodedWord(ew) => Box::new(iter::once(Text::Literal(ew))),
        }
    }
}

impl IntoTextIter for Word {
    fn iter_text(self) -> Box<dyn Iterator<Item=Text>> {
        match self {
            Word::Atom(a) => Box::new(iter::once(Text::Atom(a))),
            Word::EncodedWord(ew) => Box::new(iter::once(Text::Literal(ew))),
            Word::QS(qc) => Box::new(qc.into_iter().flat_map(IntoTextIter::iter_text)),
        }
    }
}

impl IntoTextIter for Vec<Word> {
    fn iter_text(self) -> Box<dyn Iterator<Item=Text>> {
        Box::new(self.into_iter().flat_map(IntoTextIter::iter_text))
    }
}

impl IntoTextIter for Vec<Text> {
    fn iter_text(self) -> Box<dyn Iterator<Item=Text>> {
        Box::new(self.into_iter())
    }
}

named!(pub atext<CBS, CBS>,
    take_while1!(|c: u8| b"!#$%&'*+-/=?^_`{|}~".contains(&c) || (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c))
);

named!(dot_atom<CBS, CBS>,
    do_parse!(
        opt!(cfws) >>
        a: recognize!(pair!(atext, many0!(pair!(tag!("."), atext)))) >>
        opt!(cfws) >>
        (a)
    )
);

named!(pub atom<CBS, CBS>,
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

named!(word<CBS, Word>,
    alt!(
        map!(_padded_encoded_word, Word::EncodedWord) |
        map!(atom, |x| Word::Atom(ascii_to_string_slice(x.0))) |
        map!(_quoted_string_parts, Word::QS)
    )
);

fn _concat_atom_and_qs<T: IntoTextIter>(input: T) -> String {
    let mut flat = input.iter_text().peekable();
    let mut out = String::new();

    while let Some(t1) = flat.next() {
        match (t1, flat.peek()) {
            (Text::Atom(v), Some(_)) => {out.push_str(&v); out.push(' ')},
            (t1, Some(Text::Atom(_))) => {out.push_str(t1.get()); out.push(' ')},
            (t1, _) => out.push_str(t1.get()),
        };
    }
    out
}

named!(display_name<CBS, String>,
    map!(many1!(word), _concat_atom_and_qs)
);

named!(local_part<CBS, CBS>,
    alt!(dot_atom | _raw_quoted_string)
);

named!(dtext<CBS, CBS>,
    take_while1!(|c: u8| (33..=90).contains(&c) || (94..=126).contains(&c))
);

named!(domain_literal<CBS, Vec<u8>>,
    do_parse!(
        opt!(cfws) >>
        tag!("[") >>
        a: many0!(tuple!(ofws, dtext)) >>
        b: ofws >>
        tag!("]") >>
        opt!(cfws) >>
        ({let mut out : Vec<u8> = vec![b'[']; out.extend(a.iter().flat_map(|(x, y)| x.iter().chain(y.0.iter()))); out.extend_from_slice(&b); out.push(b']'); out})
    )
);

named!(domain<CBS, Vec<u8>>,
    alt!(map!(dot_atom, |x| x.0.to_vec()) | domain_literal)
);

named!(addr_spec<CBS, String>,
    do_parse!(
        lp: local_part >>
        tag!("@") >>
        domain: domain >>
        (ascii_to_string(lp.iter().chain(b"@".iter()).chain(domain.iter()).cloned().collect::<Vec<_>>()))
    )
);

named!(angle_addr<CBS, String>,
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

named!(mailbox_list<CBS, Vec<Mailbox>>,
    do_parse!(
        a: mailbox >>
        b: fold_many0!(do_parse!(tag!(",") >> mbox: mailbox >> (mbox)), vec![a],
                       |mut acc: Vec<_>, item| {acc.push(item); acc}) >>
        (b)
    )
);

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

named!(address_list<CBS, Vec<Address>>,
    do_parse!(
        a: address >>
        b: fold_many0!(do_parse!(tag!(",") >> addr: address >> (addr)), vec![a],
                       |mut acc: Vec<_>, item| {acc.push(item); acc}) >>
        (b)
    )
);

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
       map!(verify!(take!(1), |c: CBS| (0x80..=0xff).contains(&c.0[0])), |x| x.0[0])
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
                    if let Some(x) = ws { out.push(Text::Literal(ascii_to_string(x))) };
                    out.push(Text::Literal(ew));
                    out.extend_from_slice(&ewcont);
                    out
                })
            ) |
            do_parse!(
                ws: opt!(fws) >>
                vc: many1!(alt!(vchar | _8bit_char)) >>
                ({let mut out = Vec::new(); if let Some(x) = ws { out.extend_from_slice(&x) }; out.extend_from_slice(&vc); vec![Text::Literal(ascii_to_string(out))]})
            )

        )) >>
        b: many0!(wsp) >>
        ({
            let mut out : Vec<Text> = a.iter().flat_map(|x| x.iter()).cloned().collect();
            if !b.is_empty() {
                out.push(Text::Literal(ascii_to_string(b)))
            }
            _concat_atom_and_qs(out)
        })
    )
);

// Updated from RFC6854
pub fn from(i: &[u8]) -> KResult<&[u8], Vec<Address>> {
    wrap_cbs_result(address_list_crlf(CBS(i)))
}

pub fn sender(i: &[u8]) -> KResult<&[u8], Address> {
    wrap_cbs_result(address_crlf(CBS(i)))
}

pub fn reply_to(i: &[u8]) -> KResult<&[u8], Vec<Address>> {
    wrap_cbs_result(address_list_crlf(CBS(i)))
}

pub fn unstructured(i: &[u8]) -> KResult<&[u8], String> {
    wrap_cbs_result(_unstructured(CBS(i)))
}
