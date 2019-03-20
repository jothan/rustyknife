//! SMTP DSN (delivery status notification) extension.

use std::borrow::Cow;
use std::str;

use crate::util::*;

use nom::is_hex_digit;
use crate::rfc5322::atom;

named!(pub(crate) hexpair<CBS, u8>,
    map_res!(take_while_m_n!(2, 2, is_hex_digit),
             |x: CBS| u8::from_str_radix(str::from_utf8(x.0).unwrap(), 16))
);

named!(hexchar<CBS, u8>,
    do_parse!(
        tag!("+") >>
        a: hexpair >>
        (a)
    )
);

named!(xchar<CBS, CBS>,
    take_while1!(|c: u8| (33..=42).contains(&c) || (44..=60).contains(&c) || (62..=126).contains(&c))
);

named!(pub(crate) xtext<CBS, Vec<u8>>,
    fold_many0!(alt!(
        map!(xchar, |x| x.0.to_vec()) |
        map!(hexchar, |x| vec![x])), Vec::new(), |mut acc: Vec<_>, x: Vec<u8>| {acc.extend_from_slice(&x); acc} )
);

named!(_printable_xtext<CBS, Vec<u8>>,
    map_opt!(xtext, |out: Vec<_>| {
        if out.iter().all(|c: &u8| (32..=126).contains(c) || b"\t\x0a\x0b\x0c\x0d".contains(c)) {
            Some(out)
        } else {
            None
        }
    })
);

named!(_original_recipient_address<CBS, (Cow<'_, str>, String)>,
    do_parse!(
        a: atom >> tag!(";") >> b: _printable_xtext >>
        (ascii_to_string(a), ascii_to_string_vec(b))
    )
);

/// The DSN return type desired by the sender.
#[derive(Debug, PartialEq)]
pub enum DSNRet {
    /// Return full the full message content.
    Full,
    /// Return only the email headers.
    Hdrs,
}

/// DSN parameters for the MAIL command.
#[derive(Debug, PartialEq)]
pub struct DSNMailParams {
    /// A mail transaction identifier provided by the sender.
    ///
    /// None if not specified.
    pub envid: Option<String>,
    /// The DSN return type desired by the sender.
    ///
    /// None if not specified.
    pub ret: Option<DSNRet>,
}

type Param<'a> = (&'a str, Option<&'a str>);

/// Parse a list of ESMTP parameters on a MAIL FROM command into a
/// [`DSNMailParams`] option block.
///
/// Returns the option block and a vector of parameters that were not
/// consumed.
/// # Examples
/// ```
/// use rustyknife::rfc3461::{dsn_mail_params, DSNRet, DSNMailParams};
/// let input = &[("RET", Some("HDRS")),
///               ("OTHER", None)];
///
/// let (params, other) = dsn_mail_params(input).unwrap();
///
/// assert_eq!(params, DSNMailParams{ envid: None, ret: Some(DSNRet::Hdrs) });
/// assert_eq!(other, [("OTHER", None)]);
/// ```
pub fn dsn_mail_params<'a>(input: &[Param<'a>]) -> Result<(DSNMailParams, Vec<Param<'a>>), &'static str>
{
    let mut out = Vec::new();
    let mut envid_val : Option<String> = None;
    let mut ret_val : Option<DSNRet> = None;

    for (name, value) in input {
        match (name.to_lowercase().as_str(), value) {
            ("ret", Some(value)) => {
                if ret_val.is_some() { return Err("Duplicate RET"); }

                ret_val = match value.to_lowercase().as_str() {
                    "full" => Some(DSNRet::Full),
                    "hdrs" => Some(DSNRet::Hdrs),
                    _ => return Err("Invalid RET")
                }
            },

            ("envid", Some(value)) => {
                if envid_val.is_some() { return Err("Duplicate ENVID"); }
                let inascii = string_to_ascii(value);
                if inascii.len() > 100 {
                    return Err("ENVID over 100 bytes");
                }
                if let Ok((_, parsed)) = exact!(CBS(&inascii), _printable_xtext) {
                    envid_val = Some(ascii_to_string_vec(parsed));
                } else {
                    return Err("Invalid ENVID");
                }
            },
            ("ret", None) => { return Err("RET without value") },
            ("envid", None) => { return Err("ENVID without value") },
            _ => {
                out.push((*name, *value))
            }
        }
    }

    Ok((DSNMailParams{envid: envid_val, ret: ret_val}, out))
}

/// Parse the ESMTP ORCPT parameter that may be present on a RCPT TO command.
///
/// Returns the address type and the decoded original recipient address.
/// # Examples
/// ```
/// use rustyknife::rfc3461::orcpt_address;
///
/// let (_, split) = orcpt_address(b"rfc822;bob@example.org").unwrap();
///
/// assert_eq!(split, ("rfc822".into(), "bob@example.org".into()));
/// ```
pub fn orcpt_address(input: &[u8]) -> KResult<&[u8], (String, String)>
{
    wrap_cbs_result(_original_recipient_address(CBS(input))).map(|(rem, (tp, addr))| (rem, (tp.into(), addr.into())))
}
