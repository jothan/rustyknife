use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::{map, recognize, verify};
use nom::multi::{fold_many0, fold_many1};
// Change this to something else that implements ParseError to get a
// different error type out of nom.
pub(crate) type NomError<'a> = ();

/// Shortcut type for taking in bytes and spitting out a success or NomError.
pub type NomResult<'a, O, E=NomError<'a>> = IResult<&'a [u8], O, E>;

macro_rules! nom_fromstr {
    ( $type:ty, $func:path ) => {
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
        impl <'a> std::convert::TryFrom<&'a str> for $type {
            type Error = nom::Err<NomError<'a>>;

            fn try_from(value: &'a str) -> Result<Self, Self::Error> {
                exact!(value.as_bytes(), $func).map(|(_, v)| v)
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

pub(crate) fn fold_prefix0<I, O, E, F, G>(mut prefix: F, mut cont: G) -> impl FnMut(I) -> IResult<I, Vec<O>, E>
    where I: Clone + PartialEq,
          F: FnMut(I) -> IResult<I, O, E>,
          G: FnMut(I) -> IResult<I, O, E>,
          E: nom::error::ParseError::<I>,
          Vec<O>: Clone,
{
    move |input: I| {
        let (rem, v1) = prefix(input)?;
        let out = vec![v1];

        fold_many0(&mut cont, out, |mut acc, value| {
            acc.push(value);
            acc
        })(rem)
    }
}

pub(crate) fn recognize_many0<I, O, E, F>(f: F) -> impl FnMut(I) -> IResult<I, I, E>
    where I: Clone + PartialEq + nom::Slice<std::ops::RangeTo<usize>> + nom::Offset,
          F: FnMut(I) -> IResult<I, O, E>,
          E: nom::error::ParseError::<I>,
{
    recognize(fold_many0(f, (), |_, _| ()))
}

pub(crate) fn recognize_many1<I, O, E, F>(f: F) -> impl FnMut(I) -> IResult<I, I, E>
    where I: Clone + PartialEq + nom::Slice<std::ops::RangeTo<usize>> + nom::Offset,
          F: FnMut(I) -> IResult<I, O, E>,
          E: nom::error::ParseError::<I>,
{
    recognize(fold_many1(f, (), |_, _| ()))
}

pub(crate) fn take1_filter<F>(pred: F) -> impl Fn(&[u8]) -> NomResult<u8>
    where F: Fn(u8) -> bool,
{
    move |input| {
        verify(map(take(1usize), |c: &[u8]| c[0]), |c| pred(*c))(input)
    }
}
