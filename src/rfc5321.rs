//! Parsers for [SMTP] command syntax
//!
//! [SMTP]: https://tools.ietf.org/html/rfc5321

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::{self, FromStr};

use nom::bytes::complete::{tag, tag_no_case, take, take_while1};
use nom::character::{is_alphanumeric, is_digit, is_hex_digit};
use nom::combinator::{map, opt, recognize, verify};
use nom::error::ParseError;
use nom::multi::{many0, many1};
use nom::sequence::{delimited, pair, preceded};

use crate::rfc5322::{atext as atom};
use crate::rfc5234::{crlf, wsp};
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

fn esmtp_keyword(input: &[u8]) -> NomResult<Keyword> {
    map(take_while1(is_alphanumeric), |x| Keyword(std::str::from_utf8(x).unwrap().into()))(input)
}

fn esmtp_value(input: &[u8]) -> NomResult<Value> {
    map(take_while1(|c| (33..=60).contains(&c) || (62..=126).contains(&c)),
        |x| Value(std::str::from_utf8(x).unwrap().into()))(input)
}

fn esmtp_param(input: &[u8]) -> NomResult<Param> {
    map(pair(esmtp_keyword, opt(preceded(tag("="), esmtp_value))),
        |(n, v)| Param(n, v))(input)
}

fn _esmtp_params(input: &[u8]) -> NomResult<Vec<Param>> {
    map(pair(esmtp_param, many0(preceded(many1(wsp), esmtp_param))),
        |(a, mut b)| { b.insert(0, a); b })(input)
}

fn ldh_str(input: &[u8]) -> NomResult<&[u8]> {
    let (_, mut out) = take_while1(|c| is_alphanumeric(c) || c == b'-')(input)?;

    while out.last() == Some(&b'-') {
        out = &out[..out.len()-1];
    }

    if out.is_empty() {
        Err(nom::Err::Error(NomError::from_error_kind(input, nom::error::ErrorKind::TakeWhile1)))
    } else {
        Ok((&input[out.len()..], out))
    }
}

fn let_dig(input: &[u8]) -> NomResult<&[u8]> {
    verify(take(1usize), |c: CBS| is_alphanumeric(c[0]))(input)
}

fn sub_domain(input: &[u8]) -> NomResult<&[u8]> {
    recognize(pair(let_dig, opt(ldh_str)))(input)
}

pub(crate) fn domain(input: &[u8]) -> NomResult<Domain> {
    map(recognize(pair(sub_domain, many0(pair(tag("."), sub_domain)))),
        |domain| Domain(str::from_utf8(domain).unwrap().into()))(input)
}

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
    )), |a| DotAtom(str::from_utf8(a).unwrap().into()))
);

#[inline]
named!(qtext_smtp<CBS, char>,
   map!(verify!(take!(1), |x: CBS| {
       let c = &x[0];
       (32..=33).contains(c) || (35..=91).contains(c) || (93..=126).contains(c)
   }), |x| x[0] as char)
);

#[inline]
named!(quoted_pair_smtp<CBS, char>,
    do_parse!(
        tag!("\\") >>
        c: map!(verify!(take!(1), |x: CBS| {
            (32..=126).contains(&x[0])
        }), |x| x[0]) >>
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
             |ip : CBS| str::from_utf8(ip).unwrap().parse()
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
            Ipv6Addr::from_str(str::from_utf8(addr).unwrap()).map(|ip| AddressLiteral::IP(ip.into()))
        }
    )
);

named!(dcontent<CBS, &'_ str>,
    map!(take_while1!(|c| (33..=90).contains(&c) || (94..=126).contains(&c)),
         |x| std::str::from_utf8(&x).unwrap())
);

named!(general_address_literal<CBS, AddressLiteral>,
    do_parse!(
        tag: ldh_str >>
        tag!(":") >>
        value: dcontent >>
        (AddressLiteral::Tagged(str::from_utf8(tag).unwrap().into(), value.into()))
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

/// Parse an SMTP EHLO command.
named!(pub ehlo_command<CBS, DomainPart>,
    do_parse!(
        tag_no_case!("EHLO ") >>
        dp: _domain_part >>
        tag!("\r\n") >>
        (dp)
    )
);

/// Parse an SMTP HELO command.
named!(pub helo_command<CBS, Domain>,
    do_parse!(
        tag_no_case!("HELO ") >>
        d: domain >>
        tag!("\r\n") >>
        (d)
    )
);

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
pub fn mail_command(input: &[u8]) -> NomResult<(ReversePath, Vec<Param>)> {
    map(delimited(tag_no_case("MAIL FROM:"),
                  pair(reverse_path, opt(preceded(tag(" "), _esmtp_params))),
                  crlf),
        |(addr, params)| (addr, params.unwrap_or_default()))(input)
}

named!(_forward_path<CBS, ForwardPath>,
    alt!(
        map!(tag_no_case!("<postmaster>"), |_| ForwardPath::PostMaster(None)) |
        do_parse!(tag_no_case!("<postmaster@") >> d: domain >> tag!(">") >> (ForwardPath::PostMaster(Some(d)))) |
        map!(path, ForwardPath::Path)
    )
);

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
named!(pub rcpt_command<CBS, (ForwardPath, Vec<Param>)>,
    do_parse!(
        tag_no_case!("RCPT TO:") >>
        path: _forward_path >>
        params: opt!(do_parse!(tag!(" ") >> p: _esmtp_params >> (p))) >>
        crlf >>
        (path, params.unwrap_or_default())
    )
);

/// Parse an SMTP DATA command.
named!(pub data_command<CBS, ()>,
    map!(tag_no_case!("DATA\r\n"), |_| ())
);

/// Parse an SMTP RSET command.
named!(pub rset_command<CBS, ()>,
    map!(tag_no_case!("RSET\r\n"), |_| ())
);

named!(_smtp_string<CBS, SMTPString>,
    alt!(map!(atom, |a| SMTPString(str::from_utf8(a).unwrap().into())) |
         map!(quoted_string, |qs| SMTPString(qs.into())))
);

/// Parse an SMTP NOOP command.
named!(pub noop_command<CBS, Option<SMTPString>>,
    do_parse!(
        tag_no_case!("NOOP") >>
        s1: opt!(do_parse!(
            tag!(" ") >>
            s2: _smtp_string >>
            (s2))) >>
        tag!("\r\n") >>
        (s1))
);

/// Parse an SMTP QUIT command.
named!(pub quit_command<CBS, ()>,
    map!(tag_no_case!("QUIT\r\n"), |_| ())
);

/// Parse an SMTP VRFY command.
named!(pub vrfy_command<CBS, SMTPString>,
    do_parse!(
        tag_no_case!("VRFY") >>
        tag!(" ") >>
        s: _smtp_string >>
        tag!("\r\n") >>
        (s))
);

/// Parse an SMTP EXPN command.
named!(pub expn_command<CBS, SMTPString>,
    do_parse!(
        tag_no_case!("EXPN") >>
        tag!(" ") >>
        s: _smtp_string >>
        tag!("\r\n") >>
        (s))
);

/// Parse an SMTP HELP command.
named!(pub help_command<CBS, Option<SMTPString>>,
    do_parse!(
        tag_no_case!("HELP") >>
        s1: opt!(do_parse!(
            tag!(" ") >>
            s2: _smtp_string >>
            (s2))) >>
        tag!("\r\n") >>
        (s1))
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
    EXPN(SMTPString),
    HELP(Option<SMTPString>),
}

/// Parse any basic SMTP command.
named!(pub command<CBS, Command>,
    alt!(
        map!(ehlo_command, Command::EHLO) |
        map!(helo_command, Command::HELO) |
        map!(mail_command, |(a, p)| Command::MAIL(a, p)) |
        map!(rcpt_command, |(a, p)| Command::RCPT(a, p)) |
        map!(data_command, |_| Command::DATA) |
        map!(rset_command, |_| Command::RSET) |
        map!(noop_command, Command::NOOP) |
        map!(quit_command, |_| Command::QUIT) |
        map!(vrfy_command, Command::VRFY) |
        map!(expn_command, Command::EXPN) |
        map!(help_command, Command::HELP)
    )
);

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
