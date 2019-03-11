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
    assert_eq!(extract_single(parsed).0, Some("atom atom atom".to_owned()));
}

#[test]
fn concat_qs() {
    let (rem, parsed) = from(b"\"no\"   \"space\"   space space \"two  space\" \"end space \" <ignored@example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(extract_single(parsed).0, Some("nospace space space two  spaceend space ".to_owned()));
}

#[test]
fn simple_from() {
    let (rem, parsed) = from(b"John Doe <jdoe@machine.example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    let (dname, addr) = extract_single(parsed);
    assert_eq!(dname, Some("John Doe".to_owned()));
    assert_eq!(addr, "jdoe@machine.example");
}

#[test]
fn simple_sender() {
    let (rem, parsed) = sender(b"Michael Jones <mjones@machine.example>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    if let Address::Mailbox(Mailbox{dname, address}) = parsed {
        assert_eq!(dname, Some("Michael Jones".to_owned()));
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
    assert_eq!(dname, Some("Mary Smith: Personal Account".to_owned()));
    assert_eq!(addr, "smith@home.example");
}

const TEST_GROUP : &'static [u8] = b"  A Group(Some people)\r\n    :Chris Jones <c@(Chris's host.)public.example>,\r\n        joe@example.org,\r\n John <jdoe@one.test> (my dear friend); (the end of the group)\r\n";

#[test]
fn group_reply_to() {
    let (rem, parsed) = reply_to(TEST_GROUP).unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed, vec![Address::Group(Group{
        dname: "A Group".to_owned(),
        members: vec![
            Mailbox { dname: Some("Chris Jones".to_owned()),
                      address: "c@public.example".to_owned()},
            Mailbox { dname: None,
                      address: "joe@example.org".to_owned() },
            Mailbox { dname: Some("John".to_owned()),
                      address: "jdoe@one.test".to_owned()}
        ]
    })]);
}

#[test]
fn multi_reply_to() {
    let (rem, parsed) = reply_to(b"Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    assert_eq!(parsed, vec![
        Address::Mailbox(Mailbox { dname: Some("Mary Smith".to_owned()),
                                   address: "mary@x.test".to_owned()}),
        Address::Mailbox(Mailbox { dname: None,
                                   address: "jdoe@example.org".to_owned()}),
        Address::Mailbox(Mailbox { dname: Some("Who?".to_owned()),
                                   address: "one@y.test".to_owned()}),
    ]);
}

#[test]
fn folded_qs() {
    let (rem, parsed) = reply_to(b"\"Mary\r\n Smith\"\r\n <mary@\r\n x.test(comment)>\r\n").unwrap();
    assert_eq!(rem.len(), 0);
    let (dname, addr) = extract_single(parsed);
    assert_eq!(dname, Some("Mary Smith".to_owned()));
    assert_eq!(addr, "mary@x.test");
}
