use rustyknife::rfc5322::*;

fn extract_single(mut input: Vec<Address>) -> (Option<String>, String) {
    assert_eq!(input.len(), 1);

    if let Address::Mailbox(Mailbox{dname, address}) = input.remove(0) {
        (dname, address)
    } else {
        unreachable!()
    }
}

#[test]
fn concat_atom() {
    let (rem, parsed) = from(b" atom  atom   atom    <ignored@example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(extract_single(parsed).0, Some("atom atom atom".into()));
}

#[test]
fn concat_qs() {
    let (rem, parsed) = from(b"\"no\"   \"space\"   space space \"two  space\" \"end space \" <ignored@example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(extract_single(parsed).0, Some("nospace space space two  spaceend space ".into()));
}

#[test]
fn simple_from() {
    let (rem, parsed) = from(b"John Doe <jdoe@machine.example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    let (dname, addr) = extract_single(parsed);
    assert_eq!(dname, Some("John Doe".into()));
    assert_eq!(addr, "jdoe@machine.example");
}

#[test]
fn simple_sender() {
    let (rem, parsed) = sender(b"Michael Jones <mjones@machine.example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    if let Address::Mailbox(Mailbox{dname, address}) = parsed {
        assert_eq!(dname, Some("Michael Jones".into()));
        assert_eq!(address, "mjones@machine.example");
    } else {
        unreachable!();
    }
}

#[test]
fn simple_reply_to() {
    let (rem, parsed) = reply_to(b"\"Mary Smith: Personal Account\" <smith@home.example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    let (dname, addr) = extract_single(parsed);
    assert_eq!(dname, Some("Mary Smith: Personal Account".into()));
    assert_eq!(addr, "smith@home.example");
}

#[test]
fn group_reply_to() {
    let (rem, parsed) = reply_to(b"  A Group(Some people)\r\n    :Chris Jones <c@(Chris's host.)public.example>,\r\n        joe@example.org,\r\n John <jdoe@one.test> (my dear friend); (the end of the group)\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed, vec![Address::Group(Group{
        dname: "A Group".into(),
        members: vec![
            Mailbox { dname: Some("Chris Jones".into()),
                      address: "c@public.example".into()},
            Mailbox { dname: None,
                      address: "joe@example.org".into() },
            Mailbox { dname: Some("John".into()),
                      address: "jdoe@one.test".into()}
        ]
    })]);
}

#[test]
fn multi_reply_to() {
    let (rem, parsed) = reply_to(b"Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed, vec![
        Address::Mailbox(Mailbox { dname: Some("Mary Smith".into()),
                                   address: "mary@x.test".into()}),
        Address::Mailbox(Mailbox { dname: None,
                                   address: "jdoe@example.org".into()}),
        Address::Mailbox(Mailbox { dname: Some("Who?".into()),
                                   address: "one@y.test".into()}),
    ]);
}

#[test]
fn folded_qs() {
    let (rem, parsed) = reply_to(b"\"Mary\r\n Smith\"\r\n <mary@\r\n x.test(comment)>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    let (dname, addr) = extract_single(parsed);
    assert_eq!(dname, Some("Mary Smith".into()));
    assert_eq!(addr, "mary@x.test");
}
