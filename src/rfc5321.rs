//! Parser for SMTP syntax.

use nom::is_alphanumeric;

use util::*;
use rfc5234::wsp;
use rfc5322::{atext as atom};

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

named!(esmtp_value<CBS, String>,
    map!(take_while1!(|c| (33..=60).contains(&c) || (62..=126).contains(&c)),
         |x| ascii_to_string(&x.0))
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

named!(ldh_str<CBS, CBS>,
    verify!(take_while1!(|c| is_alphanumeric(c) || c == b'-'), |x: CBS| {
        x.0.last() != Some(&b'-')
    })
);

named!(let_dig<CBS, CBS>,
    verify!(take!(1), |c: CBS| is_alphanumeric(c.0[0]))
);

named!(sub_domain<CBS, CBS>,
    recognize!(do_parse!(
        let_dig >>
        opt!(ldh_str) >>
        (())
    ))
);

named!(domain<CBS, CBS>,
    recognize!(do_parse!(
        sub_domain >>
        many0!(do_parse!(tag!(".") >> sub_domain >> (()))) >>
        (())
    ))
);

named!(at_domain<CBS, ()>,
    do_parse!(
        tag!("@") >>
        domain >>
        (())
    )
);

named!(a_d_l<CBS, ()>,
    do_parse!(
        at_domain >>
        many0!(do_parse!(tag!(",") >> at_domain >> (()))) >>
        (())
    )
);

named!(dot_string<CBS, CBS>,
    recognize!(do_parse!(
        atom >>
        many0!(do_parse!(tag!(".") >> atom >> (()))) >>
        (())
    ))
);

named!(qtext_smtp<CBS, u8>,
   map!(verify!(take!(1), |x: CBS| {
       let c = &x.0[0];
       (32..=33).contains(c) || (35..=91).contains(c) || (93..=126).contains(c)
   }), |x| x.0[0])
);

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

pub fn esmtp_params(i: &[u8]) -> KResult<&[u8], Vec<EsmtpParam>> {
    wrap_cbs_result(_esmtp_params(CBS(i)))
}

named!(quoted_string<CBS, Vec<u8>>,
    do_parse!(
        tag!("\"") >>
        qc: many0!(qcontent_smtp) >>
        tag!("\"") >>
        (qc)
    )
);

named!(local_part<CBS, CBS>,
    recognize!(alt!(map!(dot_string, |_| ()) | map!(quoted_string, |_| ())))
);

// FIXME: does not validate literals
named!(address_literal<CBS, CBS>,
    recognize!(do_parse!(
        tag!("[") >>
        take_until1!("]") >>
        tag!("]") >>
        (())
    ))
);

named!(mailbox<CBS, String>,
    map!(recognize!(do_parse!(
        local_part >>
        tag!("@") >>
        alt!(domain | address_literal) >>
        (())
    )), |x| ascii_to_string(x.0))
);

named!(path<CBS, String>,
    do_parse!(
        tag!("<") >>
        opt!(do_parse!(a_d_l >> tag!(":") >> (()))) >>
        m: mailbox >>
        tag!(">") >>
        (m)
    )
);

named!(reverse_path<CBS, String>,
    alt!(path | map!(tag!("<>"), |_| "".to_string()))
);

named!(_mail_command<CBS, (String, Vec<EsmtpParam>)>,
    do_parse!(
        tag_no_case!("MAIL FROM:") >>
        addr: reverse_path >>
        params: opt!(do_parse!(tag!(" ") >> p: _esmtp_params >> (p))) >>
        ((addr, params.unwrap_or_else(|| vec![])))
    )
);

named!(_rcpt_command<CBS, (String, Vec<EsmtpParam>)>,
    do_parse!(
        tag_no_case!("RCPT TO:") >>
        addr: alt!(
            // FIXME: Handle the postmaster case better.
            map!(tag_no_case!("<postmaster>"), |_| "postmaster@invalid".to_string()) |
            path
        ) >>
        params: opt!(do_parse!(tag!(" ") >> p: _esmtp_params >> (p))) >>
        ((addr, params.unwrap_or_else(|| vec![])))
    )
);

pub fn mail_command(i: &[u8]) -> KResult<&[u8], (String, Vec<EsmtpParam>)> {
    wrap_cbs_result(exact!(CBS(i), _mail_command))
}

pub fn rcpt_command(i: &[u8]) -> KResult<&[u8], (String, Vec<EsmtpParam>)> {
    wrap_cbs_result(exact!(CBS(i), _rcpt_command))
}

/// Validates an email address.
/// Does not accept the empty address.
pub fn validate_address(i: &[u8]) -> bool {
    exact!(CBS(i), mailbox).is_ok()
}
