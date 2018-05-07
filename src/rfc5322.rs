//! Parsers for Internet Message Format messages.
//!
//! Comments are ignored. RFC2047 decoding is applied where appropriate.

use rfc2047::encoded_word;
use rfc5234::*;
use util::*;

named!(quoted_pair<CBS, CBS>,
       do_parse!(
           tag!("\\") >>
           v: alt!(vchar | wsp) >> (v)
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
       alt!(map!(alt!(ctext | quoted_pair), |x| CommentContent::Text(x.0.to_vec())) | map!(comment, |y| CommentContent::Comment(y)))
);

named!(fws<CBS, Vec<u8>>,
    map!(pair!(opt!(do_parse!(
        a: many0!(wsp) >>
            crlf >> //CRLF is "semantically invisible"
        (a)
    )), many1!(wsp)), |(a, b)| {
        a.unwrap_or(vec![]).iter().chain(b.iter()).flat_map(|i| i.0.iter().cloned()).collect()
    })
);


named!(pub ofws<CBS, Vec<u8>>,
       map!(opt!(fws), |i| i.unwrap_or(Vec::new()))
);

fn _concat_comment(comments: &Vec<CommentContent>) -> Vec<CommentContent> {
    let mut out = Vec::new();
    let mut prev_text = false;

    for comment in comments {
        let (is_text, val) = match comment {
            CommentContent::Text(text) => {
                if text.is_empty() {
                    continue;
                }
                if prev_text {
                    if let Some(CommentContent::Text(mut pt)) = out.pop() {
                        pt.extend(text);
                        (true, CommentContent::Text(pt))
                    } else {
                        continue;
                    }
                } else {
                    (true, comment.clone())
                }
            }
            CommentContent::Comment(cmt) => {
                (false, CommentContent::Comment(cmt.clone()))
            },
        };
        prev_text = is_text;
        out.push(val);
    }

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
        ({let mut out = a.clone(); out.push(CommentContent::Text(b)); _concat_comment(&out)})
    )
);

named!(cfws<CBS, CBS>,
    alt!(recognize!(pair!(many1!(pair!(opt!(fws), comment)), opt!(fws))) | recognize!(fws))
);

named!(qtext<CBS, CBS>,
    take_while1!(|c: u8| c == 33 || (35..=91).contains(&c) || (93..=126).contains(&c))
);

named!(qcontent<CBS, CBS>,
    alt!(qtext | quoted_pair)
);

named!(quoted_string<CBS, Vec<u8>>,
    do_parse!(
        opt!(cfws) >>
        tag!("\"") >>
        a: many0!(tuple!(ofws, qcontent)) >>
        b: ofws >>
        tag!("\"") >>
        opt!(cfws) >>
        (a.iter().flat_map(|(fws, cont)| fws.iter().chain(cont.0.iter())).cloned().chain(b.iter().cloned()).collect())
    )
);

#[derive(Clone, Debug)]
pub struct Mailbox {
    pub dname: Option<String>,
    pub address: String,
}

#[derive(Clone, Debug)]
pub struct Group {
    pub dname: String,
    pub members: Vec<Mailbox>,
}

#[derive(Clone, Debug)]
pub enum Address {
    Mailbox(Mailbox),
    Group(Group),
}

#[derive(Clone, Debug)]
enum Word {
    EncodedWord(String),
    Atom(String),
    QS(String),
}

impl Word {
    fn get(&self) -> &str {
        match self {
            Word::EncodedWord(x) => x,
            Word::Atom(x) => x,
            Word::QS(x) => x,
        }
    }
}

named!(atext<CBS, CBS>,
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
        map!(_padded_encoded_word, |x| Word::EncodedWord(x)) |
        map!(atom, |x| Word::Atom(ascii_to_string(x.0))) |
        map!(quoted_string, |x| Word::QS(ascii_to_string(&x)))
    )
);

fn _concat_atom_and_qs(input: &Vec<Word>) -> String {
    let mut out = String::new();

    for (i, t1) in input.iter().enumerate() {
        let t2 = match input.get(i+1) {
            Some(x) => x,
            None => {out.extend(t1.get().chars()); continue},
        };

        match (t1, t2) {
            (Word::QS(v), Word::QS(_)) => out.extend(v.chars()),
            (Word::EncodedWord(v), Word::EncodedWord(_)) => out.extend(v.chars()),
            (_, _) => {out.extend(t1.get().chars()); out.push(' ')},
        };
    }
    out
}

named!(display_name<CBS, String>,
    map!(many1!(word), |x| _concat_atom_and_qs(&x))
);

named!(local_part<CBS, Vec<u8>>,
    alt!(map!(dot_atom, |x| x.0.to_vec()) | quoted_string)
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
        ({let mut out : Vec<u8> = vec![b'[']; out.extend(a.iter().flat_map(|(x, y)| x.iter().chain(y.0.iter()))); out.extend(b); out.push(b']'); out})
    )
);

named!(domain<CBS, Vec<u8>>,
    alt!(map!(dot_atom, |x| x.0.to_vec()) | domain_literal)
);

named!(addr_spec<CBS, Vec<u8>>,
    do_parse!(
        lp: local_part >>
        tag!("@") >>
        domain: domain >>
        ([&lp[..], b"@", &domain[..]].iter().flat_map(|x| x.iter()).cloned().collect())
    )
);

named!(angle_addr<CBS, Vec<u8>>,
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
        (Mailbox{dname, address: ascii_to_string(&address)})
    )
);

named!(mailbox<CBS, Mailbox>,
    alt!(name_addr | map!(addr_spec, |a| Mailbox{dname: None, address: ascii_to_string(&a)}))
);

named!(mailbox_list<CBS, Vec<Mailbox>>,
    do_parse!(
        a: mailbox >>
        b: many0!(pair!(tag!(","), mailbox)) >>
        ({let mut out = vec![a]; out.extend(b.iter().map(|(_, m)| m.clone())); out})
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
        (Group{dname, members: members.unwrap_or(vec![])})
    )
);

named!(address<CBS, Address>,
    alt!(map!(mailbox, |x| Address::Mailbox(x)) | map!(group, |x| Address::Group(x)))
);

named!(address_list<CBS, Vec<Address>>,
    do_parse!(
        a: address >>
        b: many0!(pair!(tag!(","), address)) >>
        ({let mut out = vec![a]; out.extend(b.iter().map(|(_, m)| m.clone())); out})
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
