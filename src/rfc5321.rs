//! Parser for SMTP syntax.

use nom::is_alphanumeric;

use util::*;
use rfc3461::xtext;
use rfc5234::wsp;

pub struct EsmtpParam(pub String, pub Option<String>);

named!(_ldh<CBS, CBS>,
    take_while1!(|c| is_alphanumeric(c) || c == b'-')
);

named!(_alphanum<CBS, CBS>,
    verify!(take!(1), |x: CBS| is_alphanumeric(x.0[0]))
);

named!(esmtp_keyword<CBS, String>,
    map!(recognize!(do_parse!(_alphanum >> many0!(_alphanum) >> ())), |x| ascii_to_string(x.0))
);

named!(_vtext<CBS, CBS>,
    verify!(take!(1), (|c: CBS| (33..=60).contains(&c.0[0]) || (62..=126).contains(&c.0[0])))
);

named!(esmtp_value<CBS, String>,
    map!(alt!(xtext | map!(_vtext, |x| x.0.to_vec())), |x| ascii_to_string(&x))
);

named!(esmtp_param<CBS, EsmtpParam>,
    do_parse!(
        name: esmtp_keyword >>
        value: opt!(pair!(tag!("="), esmtp_value)) >>
        (EsmtpParam(name, value.map(|x| x.1)))
    )
);

named!(_esmtp_params<CBS, Vec<EsmtpParam>>,
    do_parse!(
        a: esmtp_param >>
        b: many0!(do_parse!(many1!(wsp) >> c: esmtp_param >> (c))) >>
        ({ let mut out = Vec::with_capacity(b.len()+1); out.push(a); out.extend(b); out })
    )
);

pub fn esmtp_params(i: &[u8]) -> KResult<&[u8], Vec<EsmtpParam>> {
    wrap_cbs_result(_esmtp_params(CBS(i)))
}
