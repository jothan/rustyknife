#![doc(include = "../README.md")]

#![feature(external_doc)]
#![warn(rust_2018_idioms)]
#![allow(elided_lifetimes_in_paths)]
#![warn(missing_docs)]

#[macro_use]
extern crate nom;

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
