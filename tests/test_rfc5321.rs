use rustyknife::rfc5321::*;

#[test]
fn empty_from() {
    let (_, (path, params)) = mail_command(b"MAIL FROM:<>").unwrap();
    assert_eq!(path, ReversePath::Null);
    assert_eq!(params, []);
}

#[test]
#[should_panic]
fn empty_rcpt() {
    rcpt_command(b"RCPT TO:<>").unwrap();
}

#[test]
#[should_panic]
fn invalid_from() {
    mail_command(b"MAIL FROM:<pa^^&*(sarobas@example.org>").unwrap();
}

#[test]
#[should_panic]
fn invalid_rcpt() {
    rcpt_command(b"RCPT TO:<pa^^&*(sarobas@example.org>").unwrap();
}

#[test]
fn esmtp_param() {
    let (_, (path, params)) = rcpt_command(b"RCPT TO:<mrbob?@example.org> ORCPT=rfc822;mrbob+AD@example.org").unwrap();
    assert_eq!(path, Path::Path("mrbob?@example.org".into()));
    assert_eq!(params, [EsmtpParam("ORCPT".into(), Some("rfc822;mrbob+AD@example.org".into()))]);
}

#[test]
fn address_literal_domain() {
    let (_, (path, params)) = rcpt_command(b"RCPT TO:<bob@[127.0.0.1]>").unwrap();
    assert_eq!(path, Path::Path("bob@[127.0.0.1]".into()));
    assert_eq!(params, []);
}

#[test]
fn esmtp_from() {
    let (_, (path, params)) = mail_command(b"MAIL FROM:<bob@example.com> RET=FULL ENVID=abc123").unwrap();
    assert_eq!(path, ReversePath::Path("bob@example.com".into()));
    assert_eq!(params, [EsmtpParam("RET".into(), Some("FULL".into())),
                        EsmtpParam("ENVID".into(), Some("abc123".into()))]);
}

#[test]
fn quoted_from() {
    let (_, (path, params)) = mail_command(b"MAIL FROM:<\"bob the \\\"great\\\"\"@example.com>").unwrap();
    assert_eq!(path, ReversePath::Path("\"bob the \\\"great\\\"\"@example.com".into()));
    assert_eq!(params, []);
}

#[test]
fn postmaster_rcpt() {
    let (_, (path, params)) = rcpt_command(b"RCPT TO:<pOstmaster>").unwrap();
    assert_eq!(path, Path::PostMaster);
    assert_eq!(params, []);
}

#[test]
fn validate() {
    assert_eq!(validate_address(b"mrbob@example.org"), true);
    assert_eq!(validate_address(b"mrbob\"@example.org"), false);
}
