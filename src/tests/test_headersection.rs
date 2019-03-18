use crate::headersection::*;

fn hs(i: &[u8]) -> Vec<HeaderField> {
    let (rem, parsed) = header_section(i).unwrap();
    assert_eq!(rem.len(), 0);
    parsed
}

#[test]
fn basic_line() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nX-Mozilla-Status2: 00800000\r\n");
    assert_eq!(parsed, [HeaderField::Valid(b"X-Mozilla-Status", b" 0001"),
                        HeaderField::Valid(b"X-Mozilla-Status2", b" 00800000")]);
}

#[test]
fn bad_nl() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nX-Mozilla-Status2: 00800000\nmore stuff\r\n");
    assert_eq!(parsed, [HeaderField::Valid(b"X-Mozilla-Status", b" 0001"),
                        HeaderField::Valid(b"X-Mozilla-Status2", b" 00800000\nmore stuff")]);
}

#[test]
fn bad_cr() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nX-Mozilla-Status2: 00800000\rmore stuff\r\n");
    assert_eq!(parsed, [HeaderField::Valid(b"X-Mozilla-Status", b" 0001"),
                        HeaderField::Valid(b"X-Mozilla-Status2", b" 00800000\rmore stuff")]);
}

#[test]
fn folded_header() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nContent-Type: multipart/alternative;\r\n  boundary=\"------------000500020107050007070009\r\nX-Mozilla-Status2: 00800000\r\n");
    assert_eq!(parsed, [HeaderField::Valid(b"X-Mozilla-Status", b" 0001"),
                        HeaderField::Valid(b"Content-Type", b" multipart/alternative;\r\n  boundary=\"------------000500020107050007070009"),
                        HeaderField::Valid(b"X-Mozilla-Status2", b" 00800000")]);
}

#[test]
fn big_garbage() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nbad header 00800000\r\nX-Mozilla-Keys: badly\nformated\nstuff is should \r w\nork#!@#$%\r^&*()_|\"}{P?><           \r\nanother bad header <4F34184B.7040006@example.com>\r\nDate: Thu, 09 Feb 2012 14:02:35 -0500\r\n");
    assert_eq!(parsed, [HeaderField::Valid(b"X-Mozilla-Status", b" 0001"),
                        HeaderField::Invalid(b"bad header 00800000"),
                        HeaderField::Valid(b"X-Mozilla-Keys", b" badly\nformated\nstuff is should \r w\nork#!@#$%\r^&*()_|\"}{P?><           "),
                        HeaderField::Invalid(b"another bad header <4F34184B.7040006@example.com>"),
                        HeaderField::Valid(b"Date", b" Thu, 09 Feb 2012 14:02:35 -0500")]);
}
