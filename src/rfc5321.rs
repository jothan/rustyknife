//! Parsers for [SMTP] command syntax
//!
//! [SMTP]: https://tools.ietf.org/html/rfc5321

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::{self, FromStr};

use nom::branch::alt;
use nom::bytes::complete::{tag, tag_no_case, take_while1, take_while_m_n};
use nom::character::{is_alphanumeric, is_digit, is_hex_digit};
use nom::combinator::{map, map_res, opt, recognize};
use nom::error::ParseError;
use nom::multi::{many0, many1, many_m_n};
use nom::sequence::{delimited, pair, preceded, separated_pair, terminated};

use crate::behaviour::{Legacy, Intl};
use crate::rfc5322::utf8_non_ascii;
use crate::rfc5234::{crlf, wsp};
use crate::types::*;
use crate::util::*;

#[allow(missing_docs)] // Mostly internal
pub trait UTF8Policy {
    fn atext(input: &[u8]) -> NomResult<char>;
    fn qtext_smtp(input: &[u8]) -> NomResult<char>;
    fn esmtp_value_char(input: &[u8]) -> NomResult<char>;
}

impl UTF8Policy for Legacy {
    fn atext(input: &[u8]) -> NomResult<char> {
        <Legacy as crate::rfc5322::UTF8Policy>::atext(input)
    }

    fn qtext_smtp(input: &[u8]) -> NomResult<char> {
        map(take1_filter(|c| (32..=33).contains(&c) || (35..=91).contains(&c) || (93..=126).contains(&c)), char::from)(input)
    }

    fn esmtp_value_char(input: &[u8]) -> NomResult<char> {
        map(take1_filter(|c| (33..=60).contains(&c) || (62..=126).contains(&c)), char::from)(input)
    }
}

impl UTF8Policy for Intl {
    fn atext(input: &[u8]) -> NomResult<char> {
        <Intl as crate::rfc5322::UTF8Policy>::atext(input)
    }

    fn qtext_smtp(input: &[u8]) -> NomResult<char> {
        alt((Legacy::qtext_smtp, utf8_non_ascii))(input)
    }

    fn esmtp_value_char(input: &[u8]) -> NomResult<char> {
        alt((Legacy::esmtp_value_char, utf8_non_ascii))(input)
    }
}

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
nom_fromstr!(Param, esmtp_param::<Intl>);

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
nom_fromstr!(Value, esmtp_value::<Intl>);

/// Path with source route.
///
/// The source route is absent when `self.1.is_empty()`.
#[derive(Clone, Debug, PartialEq)]
pub struct Path(pub Mailbox, pub Vec<Domain>);
nom_fromstr!(Path, path::<Intl>);

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
nom_fromstr!(ForwardPath, _forward_path::<Intl>);

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
nom_fromstr!(ReversePath, reverse_path::<Intl>);

impl Display for ReversePath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReversePath::Path(p) => write!(f, "<{}>", p.0),
            ReversePath::Null => write!(f, "<>"),
        }
    }
}

fn _is_ldh(c: u8) -> bool {
    is_alphanumeric(c) || c == b'-'
}

fn esmtp_keyword(input: &[u8]) -> NomResult<Keyword> {
    map(recognize(pair(take1_filter(is_alphanumeric), recognize_many0(take1_filter(_is_ldh)))),
        |x| Keyword(std::str::from_utf8(x).unwrap().into()))(input)
}

fn esmtp_value<P: UTF8Policy>(input: &[u8]) -> NomResult<Value> {
    map(recognize_many1(P::esmtp_value_char),
        |x| Value(std::str::from_utf8(x).unwrap().into()))(input)
}

fn esmtp_param<P: UTF8Policy>(input: &[u8]) -> NomResult<Param> {
    map(pair(esmtp_keyword, opt(preceded(tag("="), esmtp_value::<P>))),
        |(n, v)| Param(n, v))(input)
}

fn _esmtp_params<P: UTF8Policy>(input: &[u8]) -> NomResult<Vec<Param>> {
    fold_prefix0(esmtp_param::<P>, preceded(many1(wsp), esmtp_param::<P>))(input)
}

fn ldh_str(input: &[u8]) -> NomResult<&[u8]> {
    let (_, mut out) = take_while1(_is_ldh)(input)?;

    while out.last() == Some(&b'-') {
        out = &out[..out.len()-1];
    }

    if out.is_empty() {
        #[allow(clippy::unit_arg)]
        Err(nom::Err::Error(NomError::from_error_kind(input, nom::error::ErrorKind::TakeWhile1)))
    } else {
        Ok((&input[out.len()..], out))
    }
}

fn let_dig(input: &[u8]) -> NomResult<u8> {
    take1_filter(is_alphanumeric)(input)
}

fn sub_domain(input: &[u8]) -> NomResult<&[u8]> {
    recognize(pair(let_dig, opt(ldh_str)))(input)
}

pub(crate) fn domain(input: &[u8]) -> NomResult<Domain> {
    map(recognize(pair(sub_domain, many0(pair(tag("."), sub_domain)))),
        |domain| Domain(str::from_utf8(domain).unwrap().into()))(input)
}

fn at_domain(input: &[u8]) -> NomResult<Domain> {
    preceded(tag("@"), domain)(input)
}

fn a_d_l(input: &[u8]) -> NomResult<Vec<Domain>> {
    fold_prefix0(at_domain, preceded(tag(","), at_domain))(input)
}

fn atom<P: UTF8Policy>(input: &[u8]) -> NomResult<&[u8]> {
    recognize_many1(P::atext)(input)
}

pub(crate) fn dot_string<P: UTF8Policy>(input: &[u8]) -> NomResult<DotAtom> {
    map(recognize(pair(atom::<P>, many0(pair(tag("."), atom::<P>)))),
        |a| DotAtom(str::from_utf8(a).unwrap().into()))(input)
}

fn quoted_pair_smtp(input: &[u8]) -> NomResult<char> {
    preceded(tag("\\"), map(take1_filter(|c| (32..=126).contains(&c)), char::from))(input)
}

fn qcontent_smtp<P: UTF8Policy>(input: &[u8]) -> NomResult<char> {
    alt((P::qtext_smtp, quoted_pair_smtp))(input)
}

pub(crate) fn quoted_string<P: UTF8Policy>(input: &[u8]) -> NomResult<QuotedString> {
    map(delimited(
        tag("\""),
        many0(qcontent_smtp::<P>),
        tag("\"")),
        |qs| QuotedString(qs.into_iter().collect()))(input)
}

pub(crate) fn local_part<P: UTF8Policy>(input: &[u8]) -> NomResult<LocalPart> {
    alt((map(dot_string::<P>, |s| s.into()),
         map(quoted_string::<P>, LocalPart::Quoted)))(input)
}

fn _ip_int(input: &[u8]) -> NomResult<u8> {
    map_res(take_while_m_n(1, 3, is_digit),
            |ip| str::from_utf8(ip).unwrap().parse())(input)
}

fn _ipv4_literal(input: &[u8]) -> NomResult<AddressLiteral> {
    map(pair(_ip_int, many_m_n(3, 3, preceded(tag("."), _ip_int))),
        |(a, b)| (AddressLiteral::IP(Ipv4Addr::new(a, b[0], b[1], b[2]).into())))(input)
}

fn _ipv6_literal(input: &[u8]) -> NomResult<AddressLiteral> {
    map_res(preceded(tag_no_case("IPv6:"), take_while1(|c| is_hex_digit(c) || b":.".contains(&c))),
            |addr| Ipv6Addr::from_str(str::from_utf8(addr).unwrap()).map(|ip| AddressLiteral::IP(ip.into())))(input)
}

fn dcontent(input: &[u8]) -> NomResult<u8> {
    take1_filter(|c| (33..=90).contains(&c) || (94..=126).contains(&c))(input)
}

fn general_address_literal(input: &[u8]) -> NomResult<AddressLiteral> {
    map(separated_pair(ldh_str, tag(":"), map(many1(dcontent), ascii_to_string)),
        |(tag, value)| AddressLiteral::Tagged(str::from_utf8(tag).unwrap().into(), value.into())
    )(input)
}

pub(crate) fn _inner_address_literal(input: &[u8]) -> NomResult<AddressLiteral> {
    alt((_ipv4_literal, _ipv6_literal, general_address_literal))(input)
}

pub(crate) fn address_literal(input: &[u8]) -> NomResult<AddressLiteral> {
    delimited(tag("["), _inner_address_literal, tag("]"))(input)
}

pub(crate) fn _domain_part(input: &[u8]) -> NomResult<DomainPart> {
    alt((map(domain, DomainPart::Domain), map(address_literal, DomainPart::Address)))(input)
}

pub(crate) fn mailbox<P: UTF8Policy>(input: &[u8]) -> NomResult<Mailbox> {
    map(separated_pair(local_part::<P>, tag("@"), _domain_part),
        |(lp, dp)| Mailbox(lp, dp))(input)
}

fn path<P: UTF8Policy>(input: &[u8]) -> NomResult<Path> {
    map(delimited(
        tag("<"),
        pair(opt(terminated(a_d_l, tag(":"))), mailbox::<P>),
        tag(">")),
        |(path, m)| Path(m, path.unwrap_or_default()))(input)
}

fn reverse_path<P: UTF8Policy>(input: &[u8]) -> NomResult<ReversePath> {
    alt((map(path::<P>, ReversePath::Path),
         map(tag("<>"), |_| ReversePath::Null)))(input)
}

/// Parse an SMTP EHLO command.
pub fn ehlo_command(input: &[u8]) -> NomResult<DomainPart> {
    delimited(tag_no_case("EHLO "), _domain_part, tag("\r\n"))(input)
}

/// Parse an SMTP HELO command.
pub fn helo_command(input: &[u8]) -> NomResult<Domain> {
    delimited(tag_no_case("HELO "), domain, tag("\r\n"))(input)
}

/// Parse an SMTP MAIL FROM command.
///
/// Returns a tuple with the reverse path and ESMTP parameters.
/// # Examples
/// ```
/// use rustyknife::behaviour::Intl;
/// use rustyknife::rfc5321::{mail_command, Param};
///
/// let (_, (rp, params)) = mail_command::<Intl>(b"MAIL FROM:<bob@example.org> BODY=8BIT\r\n").unwrap();
///
/// assert_eq!(rp.to_string(), "<bob@example.org>");
/// assert_eq!(params, [Param::new("BODY", Some("8BIT")).unwrap()]);
/// ```
pub fn mail_command<P: UTF8Policy>(input: &[u8]) -> NomResult<(ReversePath, Vec<Param>)> {
    map(delimited(tag_no_case("MAIL FROM:"),
                  pair(reverse_path::<P>, opt(preceded(tag(" "), _esmtp_params::<P>))),
                  crlf),
        |(addr, params)| (addr, params.unwrap_or_default()))(input)
}

fn _forward_path<P: UTF8Policy>(input: &[u8]) -> NomResult<ForwardPath> {
    alt((map(tag_no_case("<postmaster>"), |_| ForwardPath::PostMaster(None)),
         map(delimited(tag_no_case("<postmaster@"), domain, tag(">")), |d| ForwardPath::PostMaster(Some(d))),
         map(path::<P>, ForwardPath::Path)
    ))(input)
}

/// Parse an SMTP RCPT TO command.
///
/// Returns a tuple with the forward path and ESMTP parameters.
/// # Examples
/// ```
/// use rustyknife::behaviour::Intl;
/// use rustyknife::rfc5321::{rcpt_command, Param};
///
/// let (_, (p, params)) = rcpt_command::<Intl>(b"RCPT TO:<bob@example.org> NOTIFY=NEVER\r\n").unwrap();
///
/// assert_eq!(p.to_string(), "<bob@example.org>");
/// assert_eq!(params, [Param::new("NOTIFY", Some("NEVER")).unwrap()]);
/// ```
pub fn rcpt_command<P: UTF8Policy>(input: &[u8]) -> NomResult<(ForwardPath, Vec<Param>)> {
    map(delimited(
        tag_no_case("RCPT TO:"),
        pair(_forward_path::<P>, opt(preceded(tag(" "), _esmtp_params::<P>))),
        crlf,
    ), |(path, params)| (path, params.unwrap_or_default()))(input)
}

/// Parse an SMTP DATA command.
pub fn data_command(input: &[u8]) -> NomResult<()> {
    map(tag_no_case("DATA\r\n"), |_| ())(input)
}

/// Parse an SMTP RSET command.
pub fn rset_command(input: &[u8]) -> NomResult<()> {
    map(tag_no_case("RSET\r\n"), |_| ())(input)
}

fn _smtp_string<P: UTF8Policy>(input: &[u8]) -> NomResult<SMTPString> {
    alt((map(atom::<P>, |a| SMTPString(str::from_utf8(a).unwrap().into())),
         map(quoted_string::<P>, |qs| SMTPString(qs.into()))))(input)
}

/// Parse an SMTP NOOP command.
pub fn noop_command<P: UTF8Policy>(input: &[u8]) -> NomResult<Option<SMTPString>> {
    delimited(tag_no_case("NOOP"),
              opt(preceded(tag(" "), _smtp_string::<P>)),
              tag("\r\n"))(input)
}

/// Parse an SMTP QUIT command.
pub fn quit_command(input: &[u8]) -> NomResult<()> {
    map(tag_no_case("QUIT\r\n"), |_| ())(input)
}

/// Parse an SMTP VRFY command.
pub fn vrfy_command<P: UTF8Policy>(input: &[u8]) -> NomResult<SMTPString> {
    delimited(tag_no_case("VRFY "), _smtp_string::<P>, tag("\r\n"))(input)
}

/// Parse an SMTP EXPN command.
pub fn expn_command<P: UTF8Policy>(input: &[u8]) -> NomResult<SMTPString> {
    delimited(tag_no_case("EXPN "), _smtp_string::<P>, tag("\r\n"))(input)
}

/// Parse an SMTP HELP command.
pub fn help_command<P: UTF8Policy>(input: &[u8]) -> NomResult<Option<SMTPString>> {
    delimited(tag_no_case("HELP"),
              opt(preceded(tag(" "), _smtp_string::<P>)),
              tag("\r\n"))(input)
}

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
pub fn command<P: UTF8Policy>(input: &[u8]) -> NomResult<Command> {
    alt((
        map(ehlo_command, Command::EHLO),
        map(helo_command, Command::HELO),
        map(mail_command::<P>, |(a, p)| Command::MAIL(a, p)),
        map(rcpt_command::<P>, |(a, p)| Command::RCPT(a, p)),
        map(data_command, |_| Command::DATA),
        map(rset_command, |_| Command::RSET),
        map(noop_command::<P>, Command::NOOP),
        map(quit_command, |_| Command::QUIT),
        map(vrfy_command::<P>, Command::VRFY),
        map(expn_command::<P>, Command::EXPN),
        map(help_command::<P>, Command::HELP),
    ))(input)
}

/// Validates an email address.
///
/// Does not accept the empty address.
/// # Examples
/// ```
/// use rustyknife::behaviour::Intl;
/// use rustyknife::rfc5321::validate_address;
///
/// assert!(validate_address::<Intl>(b"bob@example.org"));
/// assert!(validate_address::<Intl>(b"bob@[aoeu:192.0.2.1]"));
/// assert!(!validate_address::<Intl>(b""));
/// ```
pub fn validate_address<P: UTF8Policy>(i: &[u8]) -> bool {
    exact!(i, mailbox::<P>).is_ok()
}
