#[macro_use]
use nom;

named!(sp,
       tag!(b" ")
);

named!(htab,
       tag!(b"\t")
);

named!(pub wsp,
       alt!(sp | htab)
);

named!(pub vchar,
       verify!(take!(1), |c: &[u8]| !c.is_empty() && (0x21..=0x7e).contains(&c[0]))
);

named!(pub crlf,
       tag!("\r\n")
);
