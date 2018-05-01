#![feature(range_contains)]

use std::env;

#[macro_use]
extern crate nom;

mod rfc5234;
use rfc5234::*;

pub mod util;
use util::*;

named!(quoted_pair<CBS, CBS>,
       do_parse!(
           tag!("\\") >>
           v: alt!(vchar | wsp) >> (v)
       )
);

named!(ctext<CBS, CBS>,
       take_while1!(|c: u8| (33..=39).contains(&c) || (42..=91).contains(&c) || (93..=126).contains(&c))
);

#[derive(Clone, Debug)]
pub enum CommentContent {
    Text(Vec<u8>),
    Comment(Vec<CommentContent>),
}

named!(ccontent<CBS, CommentContent>,
       alt!(map!(alt!(ctext | quoted_pair), |x| CommentContent::Text(x.0.to_vec())) | map!(comment, |y| CommentContent::Comment(y)))
);

named!(fws<CBS, Vec<u8>>,
    map!(pair!(opt!(do_parse!(
        a: many0!(wsp) >>
            crlf >> //CRLF is "semantically invisible"
        (a)
    )), many1!(wsp)), |(a, b)| {
        a.unwrap_or(vec![]).iter().chain(b.iter()).flat_map(|i| i.0.iter().cloned()).collect()
    })
);


named!(ofws<CBS, Vec<u8>>,
       map!(opt!(fws), |i| i.unwrap_or(Vec::new()))
);

fn _concat_comment(comments: &Vec<CommentContent>) -> Vec<CommentContent> {
    let mut out = Vec::new();
    let mut prev_text = false;

    for comment in comments {
        let (is_text, val) = match comment {
            CommentContent::Text(text) => {
                if text.is_empty() {
                    continue;
                }
                if prev_text {
                    if let Some(CommentContent::Text(mut pt)) = out.pop() {
                        pt.extend(text);
                        (true, CommentContent::Text(pt))
                    } else {
                        continue;
                    }
                } else {
                    (true, comment.clone())
                }
            }
            CommentContent::Comment(cmt) => {
                (false, CommentContent::Comment(cmt.clone()))
            },
        };
        prev_text = is_text;
        out.push(val);
    }

    out
}

named!(pub comment<CBS, Vec<CommentContent>>,
    do_parse!(
        tag!("(") >>
        a: fold_many0!(tuple!(ofws, ccontent), Vec::new(), |mut acc: Vec<_>, (fws, cc)| {
            acc.push(CommentContent::Text(fws));
            acc.push(cc);
            acc
        }) >>
        b: ofws >>
        tag!(")") >>
        ({let mut out = a.clone(); out.push(CommentContent::Text(b)); _concat_comment(&out)})
    )
);

fn main() {
    let args: Vec<String> = env::args().collect();
    let (rem, parsed) = comment(CBS(&args[1].as_bytes())).unwrap();
    
    println!("'{:?}'", parsed);
    println!("'{}'", String::from_utf8_lossy(rem.0));
}
