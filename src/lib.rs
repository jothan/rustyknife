#![cfg(feature="nightly")]
#![feature(external_doc)]

#![cfg(feature="nightly")]
#![doc(include = "../README.md")]

#![warn(rust_2018_idioms)]
#![allow(elided_lifetimes_in_paths)]
#![warn(missing_docs)]

#[macro_use]
extern crate nom;

/// Types used for varying parser behaviour.
pub mod behaviour {
    /// Octets above 127 are replaced by a replacement character.
    pub struct Legacy;

    /// Octets above 127 are interpreted as UTF-8.
    ///
    ///  * Activates message/global (RFC6532) support for message content.
    ///  * Activates SMTPUTF8 support for SMTP.
    pub struct Intl;
}

#[macro_use]
mod util;
mod rfc5234;
pub mod rfc2047;
pub mod rfc2231;
pub mod rfc5321;
pub mod rfc5322;
pub mod rfc3461;
pub mod types;
pub mod headersection;
pub mod xforward;

#[cfg(feature = "python")]
mod pymod;

#[cfg(test)]
mod tests;

pub use util::NomResult;
