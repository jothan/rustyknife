use nom::types::CompleteByteSlice;

pub type CBS<'a> = CompleteByteSlice<'a>;

#[allow(non_snake_case)]
pub fn CBS<'a>(input: &'a[u8]) -> CBS<'a> {
    CompleteByteSlice(input)
}
