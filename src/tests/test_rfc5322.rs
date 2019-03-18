use crate::rfc5322::*;
use crate::rfc5321::{LocalPart, DomainPart, Mailbox as SMTPMailbox};

fn parse_single<'a, E, F>(syntax: F, input: &'a [u8]) -> Mailbox
    where F: Fn(&'a [u8]) -> Result<(&'a [u8], Vec<Address>), E>,
          E: std::fmt::Debug
{
    let (rem, mut parsed) = syntax(input).unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed.len(), 1);

    match parsed.remove(0) {
        Address::Mailbox(mbox) => mbox,
        _ => unreachable!(),
    }
}

#[test]
fn concat_atom() {
    assert_eq!(parse_single(from, b" atom                 <ignored@example>").dname, Some("atom".into()));
    assert_eq!(parse_single(from, b" atom  atom           <ignored@example>").dname, Some("atom atom".into()));
    assert_eq!(parse_single(from, b" atom  atom   atom    <ignored@example>").dname, Some("atom atom atom".into()));
}

#[test]
fn concat_qs() {
    let parsed = parse_single(from, b"\"no\"   \"space\"   space space \"two  space\" \"end space \" <ignored@example>\r\n");
    assert_eq!(parsed.dname, Some("nospace space space two  spaceend space ".into()));
}

#[test]
fn simple_from() {
    let parsed = parse_single(from, b"John Doe <jdoe@machine.example>\r\n");
    assert_eq!(parsed.dname, Some("John Doe".into()));
    assert_eq!(parsed.address, SMTPMailbox(LocalPart::Atom("jdoe".into()), DomainPart::Domain("machine.example".into())))
}

#[test]
fn simple_sender() {
    let (rem, parsed) = sender(b"Michael Jones <mjones@machine.example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    if let Address::Mailbox(Mailbox{dname, address}) = parsed {
        assert_eq!(dname, Some("Michael Jones".into()));
        assert_eq!(address, SMTPMailbox(LocalPart::Atom("mjones".into()), DomainPart::Domain("machine.example".into())))
    } else {
        unreachable!();
    }
}

#[test]
fn simple_reply_to() {
    let parsed = parse_single(reply_to, b"\"Mary Smith: Personal Account\" <smith@home.example>\r\n");
    assert_eq!(parsed.dname, Some("Mary Smith: Personal Account".into()));
    assert_eq!(parsed.address, SMTPMailbox(LocalPart::Atom("smith".into()), DomainPart::Domain("home.example".into())))
}

#[test]
fn group_reply_to() {
    let (rem, parsed) = reply_to(b"  A Group(Some people)\r\n    :Chris Jones <c@(Chris's host.)public.example>,\r\n        joe@example.org,\r\n John <jdoe@one.test> (my dear friend); (the end of the group)\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed, [Address::Group(Group{
        dname: "A Group".into(),
        members: vec![
            Mailbox { dname: Some("Chris Jones".into()),
                      address: SMTPMailbox(LocalPart::Atom("c".into()), DomainPart::Domain("public.example".into()))},
            Mailbox { dname: None,
                      address: SMTPMailbox(LocalPart::Atom("joe".into()), DomainPart::Domain("example.org".into()))},
            Mailbox { dname: Some("John".into()),
                      address: SMTPMailbox(LocalPart::Atom("jdoe".into()), DomainPart::Domain("one.test".into()))},
        ]
    })]);
}

#[test]
fn multi_reply_to() {
    let (rem, parsed) = reply_to(b"Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed, [
        Address::Mailbox(Mailbox { dname: Some("Mary Smith".into()),
                                   address: SMTPMailbox(LocalPart::Atom("mary".into()), DomainPart::Domain("x.test".into()))}),
        Address::Mailbox(Mailbox { dname: None,
                                   address: SMTPMailbox(LocalPart::Atom("jdoe".into()), DomainPart::Domain("example.org".into()))}),
        Address::Mailbox(Mailbox { dname: Some("Who?".into()),
                                   address: SMTPMailbox(LocalPart::Atom("one".into()), DomainPart::Domain("y.test".into()))}),
    ]);
}

#[test]
fn folded_qs() {
    let parsed = parse_single(reply_to, b"\"Mary\r\n Smith\"\r\n <mary@\r\n x.test(comment)>\r\n");
    assert_eq!(parsed.dname, Some("Mary Smith".into()));
    assert_eq!(parsed.address, SMTPMailbox(LocalPart::Atom("mary".into()), DomainPart::Domain("x.test".into())));
}

#[test]
fn intl_subject() {
    let (rem, parsed) = unstructured(b"=?x-sjis?B?lEWWQI7Kg4GM9ZTygs6CtSiPzik=?=").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed, "忍法写メ光飛ばし(笑)");
}
