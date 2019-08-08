use std::borrow::Cow;
use std::str;

use nom::IResult;
use nom::multi::fold_many0;
// Change this to something else that implements ParseError to get a
// different error type out of nom.
pub(crate) type NomError<'a> = ();
pub(crate) type NomResult<'a, O, E=NomError<'a>> = IResult<&'a [u8], O, E>;

pub fn ascii_to_string<T: AsRef<[u8]> + ?Sized>(i: &T) -> Cow<str> {
    String::from_utf8_lossy(i.as_ref())
}

pub fn ascii_to_string_vec(i: Vec<u8>) -> String {
    if i.is_ascii() {
        String::from_utf8(i).unwrap()
    } else {
        String::from_utf8_lossy(&i).into_owned()
    }
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
            type Error = nom::Err<NomError<'a>>;

            fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
                exact!(value, $func).map(|(_, v)| v)
            }
        }
    }
}

macro_rules! nom_from_smtp {
    ( $smtp_func:path ) => {
        /// Parse using SMTP syntax.
        pub fn from_smtp(value: &[u8]) -> Result<Self, nom::Err<NomError>> {
            exact!(value, $smtp_func).map(|(_, v)| v)
        }
    }
}
macro_rules! nom_from_imf {
    ( $imf_func:path ) => {
        /// Parse using Internet Message Format syntax.
        pub fn from_imf(value: &[u8]) -> Result<Self, nom::Err<NomError>> {
            exact!(value, $imf_func).map(|(_, v)| v)
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

pub(crate) fn fold_prefix0<I, O, E, F, G>(prefix: F, cont: G) -> impl Fn(I) -> IResult<I, Vec<O>, E>
    where I: Clone + PartialEq,
          F: Fn(I) -> IResult<I, O, E>,
          G: Fn(I) -> IResult<I, O, E>,
          E: nom::error::ParseError::<I>,
          Vec<O>: Clone,
{
    move |input: I| {
        let (rem, v1) = prefix(input)?;
        let out = vec![v1];

        fold_many0(&cont, out, |mut acc, value| {
            acc.push(value);
            acc
        })(rem)
    }
}
