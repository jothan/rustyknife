use std::fmt::Debug;

use rfc5322::{Address, Mailbox, Group, from, sender, reply_to, KResult};

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

    Ok(())
}
