//! Parsers for [SMTP] command syntax
//!
//! [SMTP]: https://tools.ietf.org/html/rfc5321

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::{self, FromStr};

use nom::{is_alphanumeric, is_digit, is_hex_digit};

use crate::rfc5234::{crlf, wsp};
use crate::rfc5322::{atext as atom};
use crate::types::*;
use crate::util::*;

/// ESMTP parameter.
///
/// Represents an ESMTP parameter.
/// # Examples
/// ```
/// use std::convert::TryFrom;
/// use rustyknife::rfc5321::Param;
///
/// // Parse a flag that may be present on a MAIL command.
/// assert_eq!(Param::try_from(b"BODY=8BIT".as_ref()).unwrap(),
///            Param::new("BODY", Some("8BIT")).unwrap());
///
/// // Parse a flag that may be present on an EXPN command.
/// assert_eq!(Param::try_from(b"SMTPUTF8".as_ref()).unwrap(),
///            Param::new("SMTPUTF8", None).unwrap());
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Param(pub Keyword, pub Option<Value>);
nom_fromstr!(Param, esmtp_param);

impl Param {
    /// Build a new parameter from string values with syntax checking.
    pub fn new<T: AsRef<[u8]>>(keyword: T, value: Option<T>) -> Result<Self, ()> {
        let value = match value {
            Some(v) => Some(Value::try_from(v.as_ref()).map_err(|_| ())?),
            None => None,
        };
        Ok(Param(Keyword::try_from(keyword.as_ref()).map_err(|_| ())?, value))
    }
}

/// ESMTP parameter keyword.
///
/// Used as the left side in an ESMTP parameter.  For example, it
/// represents the "BODY" string in a parameter "BODY=8BIT".
#[derive(Clone, PartialEq)]
pub struct Keyword(pub(crate) String);
string_newtype!(Keyword);
nom_fromstr!(Keyword, esmtp_keyword);

/// ESMTP parameter value.
///
/// Used as the right side in an ESMTP parameter.  For example, it
/// represents the "8BIT" string in a parameter "BODY=8BIT".
#[derive(Clone, PartialEq)]
pub struct Value(pub(crate) String);
string_newtype!(Value);
nom_fromstr!(Value, esmtp_value);

/// Path with source route.
///
/// The source route is absent when `self.1.is_empty()`.
#[derive(Clone, Debug, PartialEq)]
pub struct Path(pub Mailbox, pub Vec<Domain>);
nom_fromstr!(Path, path);

/// A generic SMTP string built from an atom or a quoted string
#[derive(Clone, PartialEq)]
pub struct SMTPString(pub(crate) String);
string_newtype!(SMTPString);

/// Represents a forward path from the `"RCPT TO"` command.
#[derive(Clone, Debug, PartialEq)]
pub enum ForwardPath {
    /// `"<person@example.org>"`
    Path(Path),
    /// - `PostMaster(None)` = `"<postmaster>"`
    /// - `PostMaster(Some("domain.example.org"))` = `"<postmaster@domain.example.org>"`
    PostMaster(Option<Domain>),
}
nom_fromstr!(ForwardPath, _forward_path);

impl Display for ForwardPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ForwardPath::Path(p) => write!(f, "<{}>", p.0),
            ForwardPath::PostMaster(None) => write!(f, "<postmaster>"),
            ForwardPath::PostMaster(Some(d)) => write!(f, "<postmaster@{}>", d),
        }
    }
}

/// Represents a reverse path from the `"MAIL FROM"` command.
#[derive(Clone, Debug, PartialEq)]
pub enum ReversePath {
    /// MAIL FROM: \<person@example.org\>
    Path(Path),
    /// MAIL FROM: \<\>
    Null,
}
nom_fromstr!(ReversePath, reverse_path);

impl Display for ReversePath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReversePath::Path(p) => write!(f, "<{}>", p.0),
            ReversePath::Null => write!(f, "<>"),
        }
    }
}

#[inline]
named!(_alphanum<CBS, CBS>,
    verify!(take!(1), |x: CBS| is_alphanumeric(x.0[0]))
);

named!(esmtp_keyword<CBS, Keyword>,
    map!(recognize!(do_parse!(_alphanum >> many0!(_alphanum) >> ())), |x| Keyword(std::str::from_utf8(&x).unwrap().into()))
);

named!(esmtp_value<CBS, Value>,
    map!(take_while1!(|c| (33..=60).contains(&c) || (62..=126).contains(&c)),
         |x| Value(std::str::from_utf8(&x).unwrap().into()))
);

named!(esmtp_param<CBS, Param>,
    do_parse!(
        name: esmtp_keyword >>
        value: opt!(do_parse!(tag!("=") >>  v: esmtp_value >> (v))) >>
        (Param(name, value))
    )
);

named!(_esmtp_params<CBS, Vec<Param>>,
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

named!(pub(crate) domain<CBS, Domain>,
    map!(recognize!(do_parse!(sub_domain >> many0!(do_parse!(tag!(".") >> sub_domain >> ())) >> ())),
         |domain| Domain(str::from_utf8(domain.0).unwrap().into()))
);

named!(at_domain<CBS, Domain>,
    do_parse!(
        tag!("@") >>
        d: domain >>
        (d)
    )
);

named!(a_d_l<CBS, Vec<Domain>>,
    do_parse!(
        f: at_domain >>
        cont: many0!(do_parse!(tag!(",") >> d: at_domain >> (d))) >>
        ({
            let mut cont = cont;
            cont.insert(0, f);
            cont
        })
    )
);

named!(pub(crate) dot_string<CBS, DotAtom>,
    map!(recognize!(do_parse!(
        atom >>
        many0!(do_parse!(tag!(".") >> atom >> ())) >>
        ()
    )), |a| DotAtom(str::from_utf8(a.0).unwrap().into()))
);

#[inline]
named!(qtext_smtp<CBS, char>,
   map!(verify!(take!(1), |x: CBS| {
       let c = &x.0[0];
       (32..=33).contains(c) || (35..=91).contains(c) || (93..=126).contains(c)
   }), |x| x.0[0] as char)
);

#[inline]
named!(quoted_pair_smtp<CBS, char>,
    do_parse!(
        tag!("\\") >>
        c: map!(verify!(take!(1), |x: CBS| {
            (32..=126).contains(&x.0[0])
        }), |x| x.0[0]) >>
        (c as char)
    )
);

named!(qcontent_smtp<CBS, char>,
    alt!(qtext_smtp | quoted_pair_smtp)
);

named!(pub(crate) quoted_string<CBS, QuotedString>,
    do_parse!(
        tag!("\"") >>
        qc: many0!(qcontent_smtp) >>
        tag!("\"") >>
        (QuotedString(qc.into_iter().collect()))
    )
);

named!(pub(crate) local_part<CBS, LocalPart>,
    alt!(map!(dot_string, |s| s.into()) |
         map!(quoted_string, LocalPart::Quoted))
);

named!(_ip_int<CBS, u8>,
    map_res!(take_while_m_n!(1, 3, is_digit),
             |ip : CBS| str::from_utf8(ip.0).unwrap().parse()
    )
);

named!(_ipv4_literal<CBS, AddressLiteral>,
    do_parse!(
        a: _ip_int >>
        b: many_m_n!(3, 3, do_parse!(tag!(".") >> i: _ip_int >> (i))) >>
        (AddressLiteral::IP(Ipv4Addr::new(a, b[0], b[1], b[2]).into()))
    )
);

named!(_ipv6_literal<CBS, AddressLiteral>,
    map_res!(do_parse!(
        tag_no_case!("IPv6:") >>
        addr: take_while1!(|c| is_hex_digit(c) || b":.".contains(&c))  >>
        (addr)),
        |addr : CBS| {
            Ipv6Addr::from_str(str::from_utf8(addr.0).unwrap()).map(|ip| AddressLiteral::IP(ip.into()))
        }
    )
);

named!(dcontent<CBS, &'_ str>,
    map!(take_while1!(|c| (33..=90).contains(&c) || (94..=126).contains(&c)),
         |x| std::str::from_utf8(&x.0).unwrap())
);

named!(general_address_literal<CBS, AddressLiteral>,
    do_parse!(
        tag: ldh_str >>
        tag!(":") >>
        value: dcontent >>
        (AddressLiteral::Tagged(str::from_utf8(tag.0).unwrap().into(), value.into()))
    )
);

named!(pub(crate) _inner_address_literal<CBS, AddressLiteral>,
    alt!(_ipv4_literal | _ipv6_literal | general_address_literal)
);

named!(pub(crate) address_literal<CBS, AddressLiteral>,
    do_parse!(
        tag!("[") >>
        lit: _inner_address_literal >>
        tag!("]") >>
        (lit)
    )
);

named!(pub(crate) _domain_part<CBS, DomainPart>,
    alt!(map!(domain, DomainPart::Domain) | map!(address_literal, DomainPart::Address))
);

named!(pub(crate) mailbox<CBS, Mailbox>,
    do_parse!(
        lp: local_part >>
        tag!("@") >>
        dp:  _domain_part >>
        (Mailbox(lp, dp))
    )
);

named!(path<CBS, Path>,
    do_parse!(
        tag!("<") >>
        path: opt!(do_parse!(p: a_d_l >> tag!(":") >> (p))) >>
        m: mailbox >>
        tag!(">") >>
        (Path(m, path.unwrap_or_default()))
    )
);

named!(reverse_path<CBS, ReversePath>,
    alt!(map!(path, ReversePath::Path) |
         map!(tag!("<>"), |_| ReversePath::Null))
);

named!(_ehlo_command<CBS, DomainPart>,
    do_parse!(
        tag_no_case!("EHLO ") >>
        dp: _domain_part >>
        tag!("\r\n") >>
        (dp)
    )
);

named!(_helo_command<CBS, Domain>,
    do_parse!(
        tag_no_case!("HELO ") >>
        d: domain >>
        tag!("\r\n") >>
        (d)
    )
);

named!(_mail_command<CBS, (ReversePath, Vec<Param>)>,
    do_parse!(
        tag_no_case!("MAIL FROM:") >>
        addr: reverse_path >>
        params: opt!(do_parse!(tag!(" ") >> p: _esmtp_params >> (p))) >>
        crlf >>
        (addr, params.unwrap_or_default())
    )
);

named!(_forward_path<CBS, ForwardPath>,
    alt!(
        map!(tag_no_case!("<postmaster>"), |_| ForwardPath::PostMaster(None)) |
        do_parse!(tag_no_case!("<postmaster@") >> d: domain >> tag!(">") >> (ForwardPath::PostMaster(Some(d)))) |
        map!(path, ForwardPath::Path)
    )
);

named!(_rcpt_command<CBS, (ForwardPath, Vec<Param>)>,
    do_parse!(
        tag_no_case!("RCPT TO:") >>
        path: _forward_path >>
        params: opt!(do_parse!(tag!(" ") >> p: _esmtp_params >> (p))) >>
        crlf >>
        (path, params.unwrap_or_default())
    )
);

named!(_data_command<CBS, ()>,
    map!(tag_no_case!("DATA\r\n"), |_| ())
);

named!(_rset_command<CBS, ()>,
    map!(tag_no_case!("RSET\r\n"), |_| ())
);

named!(_smtp_string<CBS, SMTPString>,
    alt!(map!(atom, |a| SMTPString(str::from_utf8(a.0).unwrap().into())) |
         map!(quoted_string, |qs| SMTPString(qs.into())))
);

named!(_noop_command<CBS, Option<SMTPString>>,
    do_parse!(
        tag_no_case!("NOOP") >>
        s1: opt!(do_parse!(
            tag!(" ") >>
            s2: _smtp_string >>
            (s2))) >>
        tag!("\r\n") >>
        (s1))
);

named!(_quit_command<CBS, ()>,
    map!(tag_no_case!("QUIT\r\n"), |_| ())
);

named!(_vrfy_command<CBS, SMTPString>,
    do_parse!(
        tag_no_case!("VRFY") >>
        tag!(" ") >>
        s: _smtp_string >>
        tag!("\r\n") >>
        (s))
);

/// The base SMTP command set
///
/// The data on each variant corresponds to the return type of the
/// *_command functions.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Command {
    EHLO(DomainPart),
    HELO(Domain),
    MAIL(ReversePath, Vec<Param>),
    RCPT(ForwardPath, Vec<Param>),
    DATA,
    RSET,
    NOOP(Option<SMTPString>),
    QUIT,
    VRFY(SMTPString),
}

named!(_command<CBS, Command>,
    alt!(
        map!(_ehlo_command, Command::EHLO) |
        map!(_helo_command, Command::HELO) |
        map!(_mail_command, |(a, p)| Command::MAIL(a, p)) |
        map!(_rcpt_command, |(a, p)| Command::RCPT(a, p)) |
        map!(_data_command, |_| Command::DATA) |
        map!(_rset_command, |_| Command::RSET) |
        map!(_noop_command, Command::NOOP) |
        map!(_quit_command, |_| Command::QUIT) |
        map!(_vrfy_command, Command::VRFY)
    )
);

/// Parse any basic SMTP command.
pub fn command(i: &[u8]) -> KResult<&[u8], Command> {
    wrap_cbs_result(_command(CBS(i)))
}

/// Parse an SMTP EHLO command.
pub fn ehlo_command(i: &[u8]) -> KResult<&[u8], DomainPart> {
    wrap_cbs_result(_ehlo_command(CBS(i)))
}

/// Parse an SMTP HELO command.
pub fn helo_command(i: &[u8]) -> KResult<&[u8], Domain> {
    wrap_cbs_result(_helo_command(CBS(i)))
}

/// Parse an SMTP MAIL FROM command.
///
/// Returns a tuple with the reverse path and ESMTP parameters.
/// # Examples
/// ```
/// use rustyknife::rfc5321::{mail_command, Param};
///
/// let (_, (rp, params)) = mail_command(b"MAIL FROM:<bob@example.org> BODY=8BIT\r\n").unwrap();
///
/// assert_eq!(rp.to_string(), "<bob@example.org>");
/// assert_eq!(params, [Param::new("BODY", Some("8BIT")).unwrap()]);
/// ```
pub fn mail_command(i: &[u8]) -> KResult<&[u8], (ReversePath, Vec<Param>)> {
    wrap_cbs_result(_mail_command(CBS(i)))
}

/// Parse an SMTP RCPT TO command.
///
/// Returns a tuple with the forward path and ESMTP parameters.
/// # Examples
/// ```
/// use rustyknife::rfc5321::{rcpt_command, Param};
///
/// let (_, (p, params)) = rcpt_command(b"RCPT TO:<bob@example.org> NOTIFY=NEVER\r\n").unwrap();
///
/// assert_eq!(p.to_string(), "<bob@example.org>");
/// assert_eq!(params, [Param::new("NOTIFY", Some("NEVER")).unwrap()]);
/// ```
pub fn rcpt_command(i: &[u8]) -> KResult<&[u8], (ForwardPath, Vec<Param>)> {
    wrap_cbs_result(_rcpt_command(CBS(i)))
}

/// Parse an SMTP DATA command.
pub fn data_command(i: &[u8]) -> KResult<&[u8], ()> {
    wrap_cbs_result(_data_command(CBS(i)))
}

/// Parse an SMTP RSET command.
pub fn rset_command(i: &[u8]) -> KResult<&[u8], ()> {
    wrap_cbs_result(_rset_command(CBS(i)))
}

/// Parse an SMTP NOOP command.
pub fn noop_command(i: &[u8]) -> KResult<&[u8], Option<SMTPString>> {
    wrap_cbs_result(_noop_command(CBS(i)))
}

/// Parse an SMTP QUIT command.
pub fn quit_command(i: &[u8]) -> KResult<&[u8], ()> {
    wrap_cbs_result(_quit_command(CBS(i)))
}

/// Parse an SMTP VRFY command.
pub fn vrfy_command(i: &[u8]) -> KResult<&[u8], SMTPString> {
    wrap_cbs_result(_vrfy_command(CBS(i)))
}

/// Validates an email address.
///
/// Does not accept the empty address.
/// # Examples
/// ```
/// use rustyknife::rfc5321::validate_address;
///
/// assert!(validate_address(b"bob@example.org"));
/// assert!(validate_address(b"bob@[aoeu:192.0.2.1]"));
/// assert!(!validate_address(b""));
/// ```
pub fn validate_address(i: &[u8]) -> bool {
    exact!(CBS(i), mailbox).is_ok()
}
