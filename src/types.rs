//! Types shared by SMTP and Internet Message Format
//!
//! IMF allows comments and folding spaces in many places but is very
//! close to the SMTP syntax.
//!
//! If glaring incompatibilites are found in practice, the [crate::rfc5321] and
//! [crate::rfc5322] modules will get their own variants of these types.
//!
//! Structs such as [`types::Domain`] and [`types::QuotedString`] are
//! newtypes around [`String`] to make sure they can only be constructed
//! from valid values.
use std::fmt::{self, Display};

use std::net::IpAddr;

use crate::behaviour::Intl;
use crate::rfc5321 as smtp;
use crate::rfc5322 as imf;
use crate::util::*;

/// A domain name such as used by DNS.
#[derive(Clone, PartialEq)]
pub struct Domain(pub(crate) String);
string_newtype!(Domain);
impl Domain {
    nom_from_smtp!(smtp::domain::<Intl>);
    nom_from_imf!(imf::_domain::<Intl>);
}

/// The local part of an address preceding the `"@"` in an email address.
#[derive(Clone, Debug, PartialEq)]
pub enum LocalPart {
    /// Simple local part with no spaces.
    DotAtom(DotAtom),
    /// Local part that may contain spaces and special characters.
    Quoted(QuotedString),
}
impl LocalPart {
    nom_from_smtp!(smtp::local_part::<Intl>);
    nom_from_imf!(imf::local_part::<Intl>);
}

impl From<QuotedString> for LocalPart {
    fn from(value: QuotedString) -> LocalPart {
        LocalPart::Quoted(value)
    }
}

impl From<DotAtom> for LocalPart {
    fn from(value: DotAtom) -> LocalPart {
        LocalPart::DotAtom(value)
    }
}

/// A quoted string that may contain spaces.
///
/// This is used in places such as SMTP local parts and IMF display
/// names.
#[derive(Clone, PartialEq)]
pub struct QuotedString(pub(crate) String);
string_newtype!(QuotedString);

impl QuotedString {
    /// Returns this string enclosed in double quotes.
    ///
    /// Double quote and backslash characters are escaped with a
    /// backslash.
    ///
    /// No attempt is made to reencode values outside the ASCII range.
    pub fn quoted(&self) -> String {
        let mut out = String::with_capacity(self.len()+2);
        out.push('"');

        for c in self.chars() {
            match c {
                '"' | '\\' => {
                    out.push('\\');
                    out.push(c);
                }
                _ => out.push(c)
            }
        }
        out.push('"');

        out
    }

    nom_from_smtp!(smtp::quoted_string::<Intl>);
    nom_from_imf!(imf::quoted_string::<Intl>);
}

/// A string consisting of atoms separated by periods.
///
/// An atom is a string that may not contain spaces or some special
/// characters such as `':'`.
///
/// See [RFC 5322] for the full syntax.
///
/// [RFC 5322]: https://tools.ietf.org/html/rfc5322#section-3.2.3
#[derive(Clone, PartialEq)]
pub struct DotAtom(pub(crate) String);
string_newtype!(DotAtom);

impl DotAtom {
    nom_from_smtp!(smtp::dot_string::<Intl>);
    nom_from_imf!(imf::dot_atom::<Intl>);
}

impl Display for LocalPart {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LocalPart::DotAtom(a) => write!(f, "{}", a),
            LocalPart::Quoted(q) => write!(f, "{}", q.quoted()),
        }
    }
}

/// The domain part of an address following the `"@"` in an email address.
#[derive(Clone, Debug, PartialEq)]
pub enum DomainPart {
    /// A DNS domain name such as `"example.org"`.
    Domain(Domain),
    /// A network address literal such as `"[192.0.2.1]"`.
    Address(AddressLiteral),
}

impl DomainPart {
    nom_from_smtp!(smtp::_domain_part::<Intl>);
    nom_from_imf!(imf::domain::<Intl>);
}

impl From<Domain> for DomainPart {
    fn from(value: Domain) -> DomainPart {
        DomainPart::Domain(value)
    }
}

impl From<AddressLiteral> for DomainPart {
    fn from(value: AddressLiteral) -> DomainPart {
        DomainPart::Address(value)
    }
}

impl Display for DomainPart {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DomainPart::Domain(d) => write!(f, "{}", d),
            DomainPart::Address(a) => write!(f, "{}", a),
        }
    }
}

/// A network address literal.
#[derive(Clone, Debug, PartialEq)]
pub enum AddressLiteral {
    /// An IPv4 or IPv6 address literal.
    /// # Examples
    /// ```
    /// use std::convert::TryFrom;
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    /// use rustyknife::types::AddressLiteral;
    ///
    /// let ipv4 = AddressLiteral::from_smtp(b"[192.0.2.1]".as_ref()).unwrap();
    /// let ipv6 = AddressLiteral::from_smtp(b"[IPv6:2001:db8::1]".as_ref()).unwrap();
    ///
    /// assert_eq!(ipv4, AddressLiteral::IP("192.0.2.1".parse().unwrap()));
    /// assert_eq!(ipv6, AddressLiteral::IP("2001:db8::1".parse().unwrap()));
    /// ```
    IP(IpAddr),
    /// An address literal in the form tag:value.
    /// # Examples
    /// ```
    /// use std::convert::TryFrom;
    /// use rustyknife::types::AddressLiteral;
    ///
    /// let lit = AddressLiteral::from_smtp(b"[x400:cn=bob,dc=example,dc=org]".as_ref()).unwrap();
    /// assert_eq!(lit, AddressLiteral::Tagged("x400".into(), "cn=bob,dc=example,dc=org".into()));
    /// ```
    Tagged(String, String),
    /// A free form address literal. Generated only by the [crate::rfc5322] module.
    FreeForm(String),
}

impl AddressLiteral {
    /// Try to upgrade a [`AddressLiteral::FreeForm`] to the more formal subtypes.
    /// # Examples
    /// ```
    /// use rustyknife::types::AddressLiteral;
    ///
    /// let valid = AddressLiteral::FreeForm("192.0.2.1".into());
    /// let invalid = AddressLiteral::FreeForm("somewhere".into());
    ///
    /// assert_eq!(valid.upgrade(), Ok(AddressLiteral::IP("192.0.2.1".parse().unwrap())));
    /// assert_eq!(invalid.upgrade(), Err(()));
    /// ```
    pub fn upgrade(&self) -> Result<Self, ()> {
        if let AddressLiteral::FreeForm(s) = self {
            let (rem, parsed) = smtp::_inner_address_literal(s.as_bytes()).map_err(|_| ())?;

            if rem.is_empty() {
                Ok(parsed)
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    nom_from_smtp!(smtp::address_literal);
    nom_from_imf!(imf::domain_literal::<Intl>);
}


impl Display for AddressLiteral {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressLiteral::IP(ip) => match ip {
                IpAddr::V4(ipv4) => write!(f, "[{}]", ipv4),
                IpAddr::V6(ipv6) => write!(f, "[IPv6:{}]", ipv6),
            },
            AddressLiteral::Tagged(tag, value) => write!(f, "[{}:{}]", tag, value),
            AddressLiteral::FreeForm(value) => write!(f, "[{}]", value),
        }
    }
}

/// A valid email address.
///
/// - `self.0` is the local part.
/// - `self.1` is the remote/domain part.
#[derive(Clone, Debug, PartialEq)]
pub struct Mailbox(pub LocalPart, pub DomainPart);

impl Mailbox {
    nom_from_smtp!(smtp::mailbox::<Intl>);
    nom_from_imf!(imf::addr_spec::<Intl>);
}

impl Display for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.0, self.1)
    }
}
