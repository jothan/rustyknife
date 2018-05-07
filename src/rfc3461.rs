//! SMTP DSN extension

use std::str;

use util::*;

use nom::is_hex_digit;
use rfc5322::atom;

named!(hexpair<CBS, u8>,
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

named!(pub xtext<CBS, Vec<u8>>,
    fold_many0!(alt!(
        map!(xchar, |x| x.0.to_vec()) |
        map!(hexchar, |x| vec![x])), Vec::new(), |mut acc: Vec<_>, x| {acc.extend(x); acc} )
);

named!(_original_recipient_address<CBS, (String, String)>,
    do_parse!(
        a: atom >> tag!(";") >> b: xtext >>
        ((ascii_to_string(a.0), ascii_to_string(&b)))
    )
);

pub fn orcpt_address(input: &Vec<u8>) -> KResult<&[u8], (String, String)>
{
    wrap_cbs_result(_original_recipient_address(CBS(input)))
}
