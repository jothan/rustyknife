use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::map;

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
    take1_filter(|c| (0x21..=0x7e).contains(&c))(input)
}

pub fn crlf(input: &[u8]) -> NomResult<&[u8]> {
    tag("\r\n")(input)
}
