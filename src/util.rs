use std::borrow::Cow;
use std::str;

use nom;
use encoding::{Encoding, EncoderTrap, DecoderTrap};
use encoding::all::ASCII;

pub(crate) type KResult<'a, I, O, E = NomError<I>> = IResult<I, O, E>;
pub type CBS<'a> = &'a [u8];
use nom::IResult;
// Change this to something else that implements ParseError to get a
// different error type out of nom.
//pub(crate) type NomError<'a> = (&'a [u8], nom::error::ErrorKind);
pub(crate) type NomError<I> = (I, nom::error::ErrorKind);
pub(crate) type NomResult<'a, O, E=NomError<&'a [u8]>> = IResult<&'a [u8], O, E>;

pub(crate) fn CBS(input: &[u8]) -> &[u8] {
    input
}

pub fn ascii_to_string<'a, T: AsRef<[u8]> + ?Sized>(i: &'a T) -> Cow<'a, str> {
    String::from_utf8_lossy(i.as_ref())
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

macro_rules! nom_fromstr {
    ( $type:ty, $func:ident ) => {
        impl std::str::FromStr for $type {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                exact!(s.as_bytes(), $func).map(|(_, r)| r).map_err(|_| ())
            }
        }
        impl <'a> std::convert::TryFrom<&'a [u8]> for $type {
            type Error = ();

            fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
                exact!(value, $func).map(|(_, v)| v).map_err(|_| ())
            }
        }
    }
}

macro_rules! nom_from_smtp {
    ( $smtp_func:path ) => {
        /// Parse using SMTP syntax.
        pub fn from_smtp(value: &[u8]) -> Option<Self> {
            exact!(value, $smtp_func).ok().map(|(_, v)| v)
        }
    }
}
macro_rules! nom_from_imf {
    ( $imf_func:path ) => {
        /// Parse using Internet Message Format syntax.
        pub fn from_imf(value: &[u8]) -> Option<Self> {
            exact!(value, $imf_func).ok().map(|(_, v)| v)
        }
    }
}

macro_rules! string_newtype {
    ( $type:ident ) => {
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
        impl From<$type> for String {
            fn from(value: $type) -> String {
                value.0
            }
        }

        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{:?}", self.0)
            }
        }
    }
}
