use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::combinator::{map, verify};

use crate::util::*;

fn sp(input: &[u8]) -> NomResult<&[u8]> {
    tag(" ")(input)
}

fn htab(input: &[u8]) -> NomResult<&[u8]> {
    tag("\t")(input)
}

pub(crate) fn wsp(input: &[u8]) -> NomResult<u8> {
    map(alt((sp, htab)), |x| x[0])(input)
}

pub fn vchar(input: &[u8]) -> NomResult<u8> {
    map(verify(take(1usize), |c: &[u8]| (0x21..=0x7e).contains(&c[0])), |x: &[u8]| x[0])(input)
}

pub fn crlf(input: &[u8]) -> NomResult<&[u8]> {
    tag("\r\n")(input)
}
