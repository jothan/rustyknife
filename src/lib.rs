//! Fast email parsing library with a Python interface.

#![feature(proc_macro, specialization, range_contains)]

#[macro_use]
extern crate nom;
extern crate pyo3;
extern crate encoding;
extern crate memmap;

mod util;
mod rfc5234;
pub mod rfc5321;
pub mod rfc5322;
pub mod rfc3461;
pub mod headersection;
pub mod xforward;

mod pymod;
pub use pymod::PyInit_rustyknife;
