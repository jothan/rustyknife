use std::borrow::Cow;
use std::ops::Deref;
use std::str;

use nom;
use nom::types::CompleteByteSlice;
use encoding::{Encoding, EncoderTrap, DecoderTrap};
use encoding::all::ASCII;

pub(crate) type KResult<I, O, E = u32> = Result<(I, O), nom::Err<I, E>>;
pub type CBS<'a> = CompleteByteSlice<'a>;

#[allow(non_snake_case)]
pub fn CBS(input: &[u8]) -> CBS {
    CompleteByteSlice(input)
}

pub fn ascii_to_string<'a, T: Deref<Target=&'a [u8]>>(i: T) -> Cow<'a, str> {
    String::from_utf8_lossy(&i)
}

pub fn ascii_to_string_vec(i: Vec<u8>) -> String {
    if i.is_ascii() {
        String::from_utf8(i).unwrap()
    } else {
        ASCII.decode(&i, DecoderTrap::Replace).unwrap()
    }
}

pub fn string_to_ascii(i: &str) -> Vec<u8> {
    ASCII.encode(&i, EncoderTrap::Replace).unwrap()
}

pub fn wrap_cbs_result<T> (r: nom::IResult<CBS, T, u32>) -> nom::IResult<&[u8], T, u32> {
    r.map(|(r, o)| (r.0, o)).map_err(|e| match e {
        nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
        nom::Err::Error(c) => nom::Err::Error(convert_context(c)),
        nom::Err::Failure(c) => nom::Err::Failure(convert_context(c)),
    })
}

pub fn convert_context(c: nom::Context<CBS>) -> nom::Context<&[u8]> {
    match c {
        nom::Context::Code(r, e) => nom::Context::Code(r.0, e),
        #[cfg(feature = "nom-verbose-errors")]
        nom::Context::List(mut v) => nom::Context::List(v.drain(..).map(|(r, e)| (r.0, e)).collect()),
    }
}

/// Strip an optionnal CRLF.
pub fn strip_crlf(i: &[u8]) -> &[u8] {
    if i.ends_with(b"\r\n") {
        &i[0..i.len()-2]
    } else {
        i
    }
}

macro_rules! nom_fromstr {
    ( $type:ty, $func:ident ) => {
        impl std::str::FromStr for $type {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                exact!(CBS(s.as_bytes()), $func).map(|(_, r)| r).map_err(|_| ())
            }
        }
        impl <'a> std::convert::TryFrom<&'a [u8]> for $type {
            type Error = nom::Err<CBS<'a>, u32>;

            fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
                exact!(CBS(value), $func).map(|(_, r)| r)
            }
        }
    }
}

macro_rules! string_newtype {
    ( $type:ident ) => {
        #[derive(Clone, PartialEq)]
        pub struct $type(pub(crate) String);

        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        impl std::convert::AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
        impl std::ops::Deref for $type {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{:?}", self.0)
            }
        }
    }
}
