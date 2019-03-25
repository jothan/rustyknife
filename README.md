# rustyknife

[![crates.io](http://meritbadge.herokuapp.com/rustyknife)](https://crates.io/crates/rustyknife)
[![Build Status](https://travis-ci.com/zerospam/rustyknife.svg?branch=master)](https://travis-ci.com/zerospam/rustyknife)
[![codecov](https://codecov.io/gh/zerospam/rustyknife/branch/master/graph/badge.svg)](https://codecov.io/gh/zerospam/rustyknife)

Email parsing library with a focus on reliably handling malformed data

Documentation:
  - [master branch]
  - [Python module]

Features:
* Python interface
* Email header parsing
* ESMTP command parsing
* Unit testing with a high coverage
* Supports internationalized email headers through [RFC 2047] and [RFC 2231] decoding
* Used to parse the content of millions of emails every day

Roadmap:
* [SMTPUTF8] support
* [UTF-8 Internationalized Email Headers] support
* Decoding of all common ESMTP extensions
* Support more email content syntax

# Examples
## Email header decoding
```rust
use rustyknife::types::{DomainPart, DotAtom, Mailbox};
use rustyknife::rfc5322::{Address, Group, Mailbox as IMFMailbox};
use rustyknife::rfc5322::from;

let (rem, parsed) = from(b"  A Group(Some people)\r
 :Chris Jones <c@(Chris's host.)public.example>,\r
 joe@example.org,\r
 John <jdoe@one.test> (my dear friend); (the end of the group)\r\n").unwrap();

// `rem` contains the unparsed remainder.
assert!(rem.is_empty());
assert_eq!(parsed, [Address::Group(Group{
       dname: "A Group".into(),
       members: vec![
           IMFMailbox { dname: Some("Chris Jones".into()),
                        address: Mailbox::from_imf(b"c@public.example").unwrap() },
           IMFMailbox { dname: None,
                        address: Mailbox::from_imf(b"joe@example.org").unwrap() },
           IMFMailbox { dname: Some("John".into()),
                        address: Mailbox::from_imf(b"jdoe@one.test").unwrap() }
       ]
   })]);
```
## ESMTP command parsing
```rust
use rustyknife::types::{Mailbox, QuotedString, Domain};
use rustyknife::rfc5321::{mail_command, Path, ReversePath, Param};

let (_, (path, params)) = mail_command(b"MAIL FROM:<\"mr bob\"@example.com> RET=FULL ENVID=abc123\r\n").unwrap();
assert_eq!(path, ReversePath::Path(
           Path(Mailbox(QuotedString::from_smtp(b"\"mr bob\"").unwrap().into(),
                        Domain::from_smtp(b"example.com").unwrap().into()),
           vec![])));
assert_eq!(params, [Param::new("RET", Some("FULL")).unwrap(),
                    Param::new("ENVID", Some("abc123")).unwrap()]);
```
## RFC 2047 encoded word decoding
```rust
use rustyknife::rfc2047::encoded_word;
let (_, decoded) = encoded_word(b"=?x-sjis?B?lEWWQI7Kg4GM9ZTygs6CtSiPzik=?=").unwrap();
assert_eq!(decoded, "忍法写メ光飛ばし(笑)");
```

[RFC 2047]: https://tools.ietf.org/html/rfc2047
[RFC 2231]: https://tools.ietf.org/html/rfc2231
[SMTPUTF8]: https://tools.ietf.org/html/rfc6531
[UTF-8 Internationalized Email Headers]: https://tools.ietf.org/html/rfc6532
[master branch]: https://zerospam.github.io/rustyknife/rustyknife/index.html
[Python module]: https://zerospam.github.io/rustyknife/sphinx/index.html
