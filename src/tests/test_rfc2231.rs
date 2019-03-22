use crate::rfc2231::*;
use crate::rfc2231::{ContentTransferEncoding as CTE, ContentDisposition as CD};


#[cfg_attr(not(feature = "quoted-string-rfc2047"), should_panic)]
#[test]
fn rfc2047() {
    let (rem, (mtype, params)) = content_type(b" message/external-body; name=\"a =?utf-8?b?w6l0w6kgYmxvcXXDqQ==?= par ZEROSPAM.eml\"").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "message/external-body");
    assert_eq!(params, [("name".into(), "a été bloqué par ZEROSPAM.eml".into())]);
}


#[test]
#[ignore]
// I am not sure if this should be supported
fn header_lf() {
    let (rem, (mtype, params)) = content_type(b"application/pdf; name=\n\t\"=?Windows-1252?Q?Fiche_d=92information_relative_=E0_la_garantie_facultati?=\n =?Windows-1252?Q?ve.pdf?=\"\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "application/pdf");
    assert_eq!(params, [("name".into(), "Fiche d’information relative à la garantie facultative.pdf".into())]);
}

#[cfg_attr(not(feature = "quoted-string-rfc2047"), should_panic)]
#[test]
fn header_crlf() {
    let (rem, (mtype, params)) = content_type(b"application/pdf; name=\r\n\t\"=?Windows-1252?Q?Fiche_d=92information_relative_=E0_la_garantie_facultati?=\r\n =?Windows-1252?Q?ve.pdf?=\"\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "application/pdf");
    assert_eq!(params, [("name".into(), "Fiche d’information relative à la garantie facultative.pdf".into())]);
}

#[cfg_attr(not(feature = "quoted-string-rfc2047"), should_panic)]
#[test]
fn attmsg1() {
    let (rem, (mtype, params)) = content_type(b"message/rfc822;\r\n name=\"=?windows-1252?Q?=5BThe_Listserve=5D_Have_you_ever_seen_somet?=\r\n =?windows-1252?Q?hing_you_couldn=92t_explain=3F=2Eeml?=\"").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "message/rfc822");
    assert_eq!(params, [("name".into(), "[The Listserve] Have you ever seen something you couldn’t explain?.eml".into())]);
}

#[test]
fn attmsg2() {
    let (rem, (disp, params)) = content_disposition(b" attachment;\r\n filename*0*=windows-1252''%5B%54%68%65%20%4C%69%73%74%73%65%72%76%65%5D%20;\r\n filename*1*=%48%61%76%65%20%79%6F%75%20%65%76%65%72%20%73%65%65%6E%20%73;\r\n filename*2*=%6F%6D%65%74%68%69%6E%67%20%79%6F%75%20%63%6F%75%6C%64%6E%92;\r\n filename*3*=%74%20%65%78%70%6C%61%69%6E%3F%2E%65%6D%6C").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(disp, CD::Attachment);
    assert_eq!(params, [("filename".into(), "[The Listserve] Have you ever seen something you couldn’t explain?.eml".into())]);
}

#[cfg_attr(not(feature = "quoted-string-rfc2047"), should_panic)]
#[test]
fn attmsg3() {
    let (rem, (mtype, params)) = content_type(b"message/rfc822;\r\n name=\"[decoupe CNC] Re: H_S_ envoyer de =?windows-1252?Q?=AB_gros_=BB_fic?=\r\n =?windows-1252?Q?hiers=2Eeml?=\"").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "message/rfc822");
    assert_eq!(params, [("name".into(), "[decoupe CNC] Re: H_S_ envoyer de « gros » fichiers.eml".into())]);
}

#[test]
fn attmsg4() {
    let (rem, (disp, params)) = content_disposition(b"attachment;\r\n filename*0*=windows-1252''%5B%64%65%63%6F%75%70%65%20%43%4E%43%5D%20%52%65;\r\n filename*1*=%3A%20%48%5F%53%5F%20%65%6E%76%6F%79%65%72%20%64%65%20%AB%20;\r\n filename*2*=%67%72%6F%73%20%BB%20%66%69%63%68%69%65%72%73%2E%65%6D%6C").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(disp, CD::Attachment);
    assert_eq!(params, [("filename".into(), "[decoupe CNC] Re: H_S_ envoyer de « gros » fichiers.eml".into())]);
}

// Cases from RFC2231 below
#[test]
fn simple_long() {
    let (rem, (mtype, mut params)) = content_type(b"message/external-body; access-type=URL;\r\n URL*0=\"ftp://\";\r\n URL*1=\"cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\"").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "message/external-body");
    params.sort();
    assert_eq!(params, [("access-type".into(), "URL".into()),
                            ("url".into(), "ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar".into())]);
}

#[test]
fn encoded_single() {
    let (rem, (mtype, params)) = content_type(b"application/x-stuff;\r\n title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "application/x-stuff");
    assert_eq!(params, [("title".into(), "This is ***fun***".into())]);
}

#[test]
fn encoded_single_no_encoding() {
    let (rem, (mtype, params)) = content_type(b"application/x-stuff;\r\n title*='en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "application/x-stuff");
    assert_eq!(params, [("title".into(), "This is ***fun***".into())]);
}

#[test]
fn cd_mixed() {
    const CASES : &[&[u8]] = &[b"inline", b"attachment", b"x-whatever"];
    for input in CASES.iter() {
        let (rem, (disp, params)) = content_disposition(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(disp.to_string(), std::str::from_utf8(*input).unwrap());
        assert_eq!(params, []);
    }
}

#[test]
fn cte_base64() {
    const CASES : &[&[u8]] = &[b"Base64", b"base64", b" base64 \r\n", b" base64\r\n", b" base64 \r\n "];
    for input in CASES.iter() {
        let (rem, parsed) = content_transfer_encoding(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed, CTE::Base64);
    }

    let (rem, parsed) = content_transfer_encoding(b" base64 aoeu").unwrap();
    assert_eq!(rem.len(), 4);
    assert_eq!(parsed, CTE::Base64);
}

#[test]
fn cte_mixed() {
    const CASES : &[&[u8]] = &[b"7bit", b"8bit", b"binary", b"base64", b"quoted-printable", b"x-whatever"];
    for input in CASES.iter() {
        let (rem, parsed) = content_transfer_encoding(input).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.to_string(), std::str::from_utf8(*input).unwrap());
    }
}

#[test]
fn encoded_mixed() {
    let (rem, (mtype, params)) = content_type(b"application/x-stuff;\r\n title*0*=us-ascii'en'This%20is%20even%20more%20;\r\n title*1*=%2A%2A%2Afun%2A%2A%2A%20;\r\n title*2=\"isn\'t it!\"").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(mtype, "application/x-stuff");
    assert_eq!(params, [("title".into(), "This is even more ***fun*** isn't it!".into())]);
}

// Selected cases from http://test.greenbytes.de/tech/tc2231/ below

macro_rules! green_tc {
    ($tname:ident, $input:expr, $disp:expr, $fname:expr) => (
        #[test]
        fn $tname() {
            let (rem, (disp, params)) = content_disposition($input).unwrap();
            assert_eq!(rem.len(), 0);
            assert_eq!(disp, $disp);
            assert_eq!(params, [("filename".into(), $fname.into())]);
        }
    )
}

green_tc!(attfnboth, b"attachment; filename=\"foo-ae.html\"; filename*=UTF-8''foo-%c3%a4.html;", CD::Attachment, "foo-ä.html");
green_tc!(attfnboth2, b"attachment; filename*=UTF-8''foo-%c3%a4.html; filename=\"foo-ae.html\"", CD::Attachment, "foo-ä.html");
green_tc!(attfnboth3, b"attachment; filename*0*=ISO-8859-15''euro-sign%3d%a4; filename*=ISO-8859-1''currency-sign%3d%a4", CD::Attachment, "euro-sign=€");
green_tc!(attfncontenc, b"attachment; filename*0*=UTF-8''foo-%c3%a4; filename*1=\".html\"", CD::Attachment, "foo-ä.html");
green_tc!(attfncontord, b"attachment; filename*1=\"bar\"; filename*0=\"foo\"", CD::Attachment, "foobar");
green_tc!(attwithasciifnescapedchar, b"inline; filename=\"f\\oo.html\"", CD::Inline, "foo.html");
green_tc!(attwithfn2231abspathdisguised, b"attachment; filename*=UTF-8''%5cfoo.html",CD::Attachment, "\\foo.html");
green_tc!(attwithfn2231utf8, b"attachment; filename*=UTF-8''foo-%c3%a4-%e2%82%ac.html", CD::Attachment, "foo-ä-€.html");
green_tc!(attwithfntokensq, b"attachment; filename='foo.bar'", CD::Attachment, "'foo.bar'");
green_tc!(attwithisofnplain, b"attachment; filename=\"foo-\xe4.html\"", CD::Attachment, "foo-\u{fffd}.html");
green_tc!(attwithquotedsemicolon, b"attachment; filename=\"Here's a semicolon;.html\"", CD::Attachment, "Here's a semicolon;.html");
green_tc!(inlwithasciifilename, b"inline; filename=\"foo.html\"", CD::Inline, "foo.html");

#[test]
#[should_panic]
fn inlonlyquoted() {
    content_disposition(b"Content-Disposition: \"inline\"").unwrap();
}

#[test]
#[should_panic]
fn attfnbrokentokenutf() {
    let (rem, _) = content_disposition(b"attachment; filename=foo-\xC3\xA4.html").unwrap();
    assert_eq!(rem.len(), 0);
}
