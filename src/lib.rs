//! Pick apart evil emails with a rusty knife.
//!
//! Collection of nom parsers for email with a Python interface.

#![warn(rust_2018_idioms)]
#![allow(elided_lifetimes_in_paths)]

#[macro_use]
extern crate nom;

mod util;
mod rfc5234;
pub mod rfc2047;
pub mod rfc2231;
pub mod rfc5321;
pub mod rfc5322;
pub mod rfc3461;
pub mod headersection;
pub mod xforward;

#[cfg(feature = "python")]
mod pymod;
