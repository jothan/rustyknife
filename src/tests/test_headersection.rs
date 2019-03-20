use crate::headersection::*;

fn hs(i: &[u8]) -> Vec<HeaderField> {
    let (rem, parsed) = header_section(i).unwrap();
    assert_eq!(rem.len(), 0);
    parsed
}

#[test]
fn basic_line() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nX-Mozilla-Status2: 00800000\r\n");
    assert_eq!(parsed, [Ok((b"X-Mozilla-Status".as_ref(), b" 0001".as_ref())),
                        Ok((b"X-Mozilla-Status2".as_ref(), b" 00800000".as_ref()))]);
}

#[test]
fn bad_nl() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nX-Mozilla-Status2: 00800000\nmore stuff\r\n".as_ref());
    assert_eq!(parsed, [Ok((b"X-Mozilla-Status".as_ref(), b" 0001".as_ref())),
                        Ok((b"X-Mozilla-Status2".as_ref(), b" 00800000\nmore stuff".as_ref()))]);
}

#[test]
fn bad_cr() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nX-Mozilla-Status2: 00800000\rmore stuff\r\n".as_ref());
    assert_eq!(parsed, [Ok((b"X-Mozilla-Status".as_ref(), b" 0001".as_ref())),
                        Ok((b"X-Mozilla-Status2".as_ref(), b" 00800000\rmore stuff".as_ref()))]);
}

#[test]
fn folded_header() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nContent-Type: multipart/alternative;\r\n  boundary=\"------------000500020107050007070009\r\nX-Mozilla-Status2: 00800000\r\n");
    assert_eq!(parsed, [Ok((b"X-Mozilla-Status".as_ref(), b" 0001".as_ref())),
                        Ok((b"Content-Type".as_ref(), b" multipart/alternative;\r\n  boundary=\"------------000500020107050007070009".as_ref())),
                        Ok((b"X-Mozilla-Status2".as_ref(), b" 00800000".as_ref()))]);
}

#[test]
fn big_garbage() {
    let parsed = hs(b"X-Mozilla-Status: 0001\r\nbad header 00800000\r\nX-Mozilla-Keys: badly\nformated\nstuff is should \r w\nork#!@#$%\r^&*()_|\"}{P?><           \r\nanother bad header <4F34184B.7040006@example.com>\r\nDate: Thu, 09 Feb 2012 14:02:35 -0500\r\n".as_ref());
    assert_eq!(parsed, [Ok((b"X-Mozilla-Status".as_ref(), b" 0001".as_ref())),
                        Err(b"bad header 00800000".as_ref()),
                        Ok((b"X-Mozilla-Keys".as_ref(), b" badly\nformated\nstuff is should \r w\nork#!@#$%\r^&*()_|\"}{P?><           ".as_ref())),
                        Err(b"another bad header <4F34184B.7040006@example.com>".as_ref()),
                        Ok((b"Date".as_ref(), b" Thu, 09 Feb 2012 14:02:35 -0500".as_ref()))]);
}
