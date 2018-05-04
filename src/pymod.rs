use std::fmt::Debug;
use std::fs::File;

use rfc5322::{Address, Mailbox, Group, from, sender, reply_to};
use headersection::{HeaderField, header_section};
use xforward::{XforwardParam, xforward_params};
use util::KResult;

use memmap::Mmap;

use pyo3::{self, Python, PyResult, PyModule, PyObject, PyBytes, PyTuple, IntoPyObject, ToPyObject, PyErr};
use pyo3::exc;
use pyo3::py::modinit as pymodinit;

impl ToPyObject for Address {
    fn to_object(&self, py: Python) -> PyObject {
        match self {
            Address::Mailbox(m) => m.to_object(py),
            Address::Group(g) => g.to_object(py),
        }
    }
}

impl ToPyObject for Group {
    fn to_object(&self, py: Python) -> PyObject {
        PyTuple::new(py, &[self.dname.to_object(py), self.members.to_object(py)]).into_object(py)
    }
}
impl ToPyObject for Mailbox {
    fn to_object(&self, py: Python) -> PyObject {
        PyTuple::new(py, &[self.dname.to_object(py), self.address.to_object(py)]).into_object(py)
    }
}

impl IntoPyObject for Address {
    fn into_object(self, py: Python) -> PyObject {
        self.to_object(py)
    }
}

impl<'a> IntoPyObject for HeaderField<'a> {
    fn into_object(self, py: Python) -> PyObject {
        self.to_object(py)
    }
}

impl<'a> ToPyObject for HeaderField<'a> {
    fn to_object(&self, py: Python) -> PyObject {
        match self {
            HeaderField::Valid(name, value) => PyTuple::new(py, &[PyBytes::new(py, name).into_object(py),
                                                                  PyBytes::new(py, value).into_object(py)]).into_object(py),
            HeaderField::Invalid(value) => PyTuple::new(py, &[None::<&[u8]>.to_object(py),
                                                              PyBytes::new(py, value).into_object(py)]).into_object(py),
        }
    }
}

impl ToPyObject for XforwardParam {
    fn to_object(&self, py: Python) -> PyObject {
        PyTuple::new(py, &[self.0.to_object(py),
                           self.1.to_object(py)]).into_object(py)
    }
}

impl IntoPyObject for XforwardParam {
    fn into_object(self, py: Python) -> PyObject {
        self.to_object(py)
    }
}

fn convert_result<O, E: Debug>  (input: KResult<&[u8], O, E>, match_all: bool) -> PyResult<O> {
    match input {
        Ok((rem, out)) => {
            if match_all && !rem.is_empty() {
                Err(PyErr::new::<exc::ValueError, _>("Whole input did not match"))
            } else {
                Ok(out)
            }
        }
        Err(err) => Err(PyErr::new::<exc::ValueError, _>(format!("{:?}.", err))),
    }
}

fn header_section_slice(py: Python, input: &[u8]) -> PyResult<PyObject> {
    let res = header_section(input)
        .map(|(rem, out)| (rem, (out, input.len().checked_sub(rem.len()).unwrap()).into_object(py)));

    convert_result(res, false)
}

#[pymodinit(rustyknife)]
fn init_module(py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "from_")]
    fn py_from(input: &PyBytes) -> PyResult<Vec<Address>> {
        convert_result(from(input.data()), true)
    }

    #[pyfn(m, "sender")]
    fn py_sender(input: &PyBytes) -> PyResult<Address> {
        convert_result(sender(input.data()), true)
    }

    #[pyfn(m, "reply_to")]
    fn py_reply_to(input: &PyBytes) -> PyResult<Vec<Address>> {
        convert_result(reply_to(input.data()), true)
    }

    #[pyfn(m, "header_section")]
    fn py_header_section(py2: Python, input: &PyBytes) -> PyResult<PyObject> {
        header_section_slice(py2, input.data())
    }

    #[pyfn(m, "header_section_file")]
    fn py_header_section_file(py2: Python, fname: &str) -> PyResult<PyObject> {
        let file = File::open(fname)?;
        let fmap = unsafe { Mmap::map(&file)? };

        header_section_slice(py2, &fmap)
    }

    #[pyfn(m, "xforward_params")]
    fn py_xforward_params(input: &PyBytes) -> PyResult<Vec<XforwardParam>> {
        convert_result(xforward_params(input.data()), true)
    }

    Ok(())
}
