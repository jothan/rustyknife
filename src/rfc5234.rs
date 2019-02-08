use crate::util::*;

named!(sp<CBS, CBS>,
       tag!(" ")
);

named!(htab<CBS, CBS>,
       tag!("\t")
);

named!(pub wsp<CBS, u8>,
       map!(alt!(sp | htab), |x| x.0[0])
);

#[inline]
named!(pub vchar<CBS, u8>,
       map!(verify!(take!(1), |c: CBS| !c.0.is_empty() && (0x21..=0x7e).contains(&c.0[0])), |x| x.0[0])
);

named!(pub crlf<CBS, CBS>,
       tag!("\r\n")
);
