//! Parser for SMTP syntax.

use std::borrow::Cow;

use nom::is_alphanumeric;

use crate::util::*;
use crate::rfc5234::wsp;
use crate::rfc5322::{atext as atom};

#[derive(Clone, Debug, PartialEq)]
pub struct EsmtpParam(pub String, pub Option<String>);

#[derive(Debug, PartialEq)]
pub enum Path {
    Mailbox(Mailbox),
    PostMaster, // RCPT TO: <postmaster>
}

#[derive(Debug, PartialEq)]
pub enum ReversePath {
    Mailbox(Mailbox),
    Null, // MAIL FROM: <>
}

#[derive(Debug, PartialEq)]
pub enum LocalPart {
    Atom(String),
    Quoted(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub enum DomainPart {
    Domain(String),
    AddressLiteral(String),
}

impl From<&LocalPart> for String {
    fn from(lp: &LocalPart) -> String {
        match lp {
            LocalPart::Atom(a) => a.clone(),
            LocalPart::Quoted(q) => quote_localpart(q),
        }
    }
}

fn quote_localpart(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());

    for c in input {
        match c {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(*c as char);
            }
            _ => out.push(*c as char)
        }
    }

    out
}

impl From<&DomainPart> for String {
    fn from(dp: &DomainPart) -> String {
        match dp {
            DomainPart::Domain(d) => d.clone(),
            DomainPart::AddressLiteral(a) => format!("[{}]", a),
        }
    }
}

impl From<&Mailbox> for String {
    fn from(mbox: &Mailbox) -> String {
        format!("{}@{}", String::from(&mbox.0), String::from(&mbox.1))
    }
}

#[derive(Debug, PartialEq)]
pub struct Mailbox(pub LocalPart, pub DomainPart);

#[inline]
named!(_alphanum<CBS, CBS>,
    verify!(take!(1), |x: CBS| is_alphanumeric(x.0[0]))
);

named!(esmtp_keyword<CBS, Cow<'_, str>>,
    map!(recognize!(do_parse!(_alphanum >> many0!(_alphanum) >> ())), |x| ascii_to_string(x))
);

named!(esmtp_value<CBS, Cow<'_, str>>,
    map!(take_while1!(|c| (33..=60).contains(&c) || (62..=126).contains(&c)),
         |x| ascii_to_string(x))
);

named!(esmtp_param<CBS, EsmtpParam>,
    do_parse!(
        name: esmtp_keyword >>
        value: opt!(do_parse!(tag!("=") >>  v: esmtp_value >> (v))) >>
        (EsmtpParam(name.into(), value.map(|v| v.into())))
    )
);

named!(_esmtp_params<CBS, Vec<EsmtpParam>>,
    do_parse!(
        a: esmtp_param >>
        b: many0!(do_parse!(many1!(wsp) >> c: esmtp_param >> (c))) >>
        ({ let mut out = Vec::with_capacity(b.len()+1); out.push(a); out.extend_from_slice(&b); out })
    )
);

named!(ldh_str<CBS, CBS>,
    verify!(take_while1!(|c| is_alphanumeric(c) || c == b'-'), |x: CBS| {
        x.0.last() != Some(&b'-')
    })
);

#[inline]
named!(let_dig<CBS, CBS>,
    verify!(take!(1), |c: CBS| is_alphanumeric(c.0[0]))
);

named!(sub_domain<CBS, CBS>,
    recognize!(do_parse!(
        let_dig >>
        opt!(ldh_str) >>
        ()
    ))
);

named!(domain<CBS, DomainPart>,
    map!(recognize!(do_parse!(sub_domain >> many0!(do_parse!(tag!(".") >> sub_domain >> ())) >> ())),
         |domain| DomainPart::Domain(ascii_to_string(domain).into())
    )
);

named!(at_domain<CBS, ()>,
    do_parse!(
        tag!("@") >>
        domain >>
        ()
    )
);

named!(a_d_l<CBS, ()>,
    do_parse!(
        at_domain >>
        many0!(do_parse!(tag!(",") >> at_domain >> ())) >>
        ()
    )
);

named!(dot_string<CBS, CBS>,
    recognize!(do_parse!(
        atom >>
        many0!(do_parse!(tag!(".") >> atom >> ())) >>
        ()
    ))
);

#[inline]
named!(qtext_smtp<CBS, u8>,
   map!(verify!(take!(1), |x: CBS| {
       let c = &x.0[0];
       (32..=33).contains(c) || (35..=91).contains(c) || (93..=126).contains(c)
   }), |x| x.0[0])
);

#[inline]
named!(quoted_pair_smtp<CBS, u8>,
    do_parse!(
        tag!("\\") >>
        c: map!(verify!(take!(1), |x: CBS| {
            let c = &x.0[0];
            (32..=126).contains(c)
        }), |x| x.0[0]) >>
        (c)
    )
);

named!(qcontent_smtp<CBS, u8>,
    alt!(qtext_smtp | quoted_pair_smtp)
);

named!(quoted_string<CBS, Vec<u8>>,
    do_parse!(
        tag!("\"") >>
        qc: many0!(qcontent_smtp) >>
        tag!("\"") >>
        (qc)
    )
);

named!(local_part<CBS, LocalPart>,
    alt!(map!(dot_string, |s| LocalPart::Atom(ascii_to_string(s).into())) | map!(quoted_string, LocalPart::Quoted))
);

// FIXME: does not validate literals
named!(address_literal<CBS, DomainPart>,
    do_parse!(
        tag!("[") >>
        dp: take_until1!("]") >>
        tag!("]") >>
        (DomainPart::AddressLiteral(ascii_to_string(dp).into()))
    )
);

named!(mailbox<CBS, Mailbox>,
    do_parse!(
        lp: local_part >>
        tag!("@") >>
        dp: alt!(domain | address_literal) >>
        (Mailbox(lp, dp))
    )
);

named!(path<CBS, Mailbox>,
    do_parse!(
        tag!("<") >>
        opt!(do_parse!(a_d_l >> tag!(":") >> ())) >>
        m: mailbox >>
        tag!(">") >>
        (m)
    )
);

named!(reverse_path<CBS, ReversePath>,
    alt!(map!(path, ReversePath::Mailbox) |
         map!(tag!("<>"), |_| ReversePath::Null))
);

named!(_mail_command<CBS, (ReversePath, Vec<EsmtpParam>)>,
    do_parse!(
        tag_no_case!("MAIL FROM:") >>
        addr: reverse_path >>
        params: opt!(do_parse!(tag!(" ") >> p: _esmtp_params >> (p))) >>
        (addr, params.unwrap_or_default())
    )
);

named!(_rcpt_command<CBS, (Path, Vec<EsmtpParam>)>,
    do_parse!(
        tag_no_case!("RCPT TO:") >>
        addr: alt!(
            map!(tag_no_case!("<postmaster>"), |_| Path::PostMaster) |
            map!(path, Path::Mailbox)
        ) >>
        params: opt!(do_parse!(tag!(" ") >> p: _esmtp_params >> (p))) >>
        (addr, params.unwrap_or_default())
    )
);

pub fn mail_command(i: &[u8]) -> KResult<&[u8], (ReversePath, Vec<EsmtpParam>)> {
    wrap_cbs_result(exact!(CBS(i), _mail_command))
}

pub fn rcpt_command(i: &[u8]) -> KResult<&[u8], (Path, Vec<EsmtpParam>)> {
    wrap_cbs_result(exact!(CBS(i), _rcpt_command))
}

/// Validates an email address.
/// Does not accept the empty address.
pub fn validate_address(i: &[u8]) -> bool {
    exact!(CBS(i), mailbox).is_ok()
}
