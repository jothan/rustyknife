use util::*;

named!(sp<CBS, CBS>,
       tag!(" ")
);

named!(htab<CBS, CBS>,
       tag!("\t")
);

named!(pub wsp<CBS, CBS>,
       alt!(sp | htab)
);

named!(pub vchar<CBS, CBS>,
       verify!(take!(1), |c: CBS| !c.0.is_empty() && (0x21..=0x7e).contains(&c.0[0]))
);

named!(pub crlf<CBS, CBS>,
       tag!("\r\n")
);
