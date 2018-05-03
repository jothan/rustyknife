use nom::types::CompleteByteSlice;
use encoding::{Encoding, DecoderTrap};
use encoding::all::ASCII;

pub type CBS<'a> = CompleteByteSlice<'a>;

#[allow(non_snake_case)]
pub fn CBS<'a>(input: &'a[u8]) -> CBS<'a> {
    CompleteByteSlice(input)
}

pub fn ascii_to_string(i: &[u8]) -> String {
    ASCII.decode(&i, DecoderTrap::Replace).unwrap()
}
