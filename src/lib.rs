#![feature(proc_macro, specialization, range_contains)]

#[macro_use]
extern crate nom;
extern crate pyo3;
extern crate encoding;

mod util;
mod rfc5234;
pub mod rfc5322;

mod pymod;
pub use pymod::PyInit_rustyknife;
