use std::fmt::Debug;
use std::fs::File;

use rfc3461::{orcpt_address, dsn_mail_params, DSNMailParams, DSNRet};
use rfc5321::{EsmtpParam, mail_command, rcpt_command, validate_address};
use rfc5322::{Address, Mailbox, Group, from, sender, reply_to};
use headersection::{HeaderField, header_section};
use xforward::{XforwardParam, xforward_params};
use util::{KResult, string_to_ascii};

use memmap::Mmap;

use pyo3::{self, Python, PyResult, PyModule, PyObject, PyBytes, PyTuple, IntoPyObject, ToPyObject, PyErr, PyDict};
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
            HeaderField::Invalid(value) => PyTuple::new(py, &[py.None(),
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

impl ToPyObject for EsmtpParam {
    fn to_object(&self, py: Python) -> PyObject {
        PyTuple::new(py, &[self.0.to_object(py),
                           self.1.to_object(py)]).into_object(py)
    }
}

impl IntoPyObject for EsmtpParam {
    fn into_object(self, py: Python) -> PyObject {
        self.to_object(py)
    }
}

impl ToPyObject for DSNMailParams {
    fn to_object(&self, py: Python) -> PyObject {
        let out = PyDict::new(py);

        out.set_item("envid", self.envid.clone()).unwrap();
        out.set_item("ret", match self.ret {
            Some(DSNRet::Hdrs) => Some("HDRS"),
            Some(DSNRet::Full) => Some("FULL"),
            None => None,
        }).unwrap();
        out.to_object(py)
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

    #[pyfn(m, "orcpt_address")]
    fn py_orcpt_address(input: &str) -> PyResult<(String, String)> {
        let inascii = string_to_ascii(&input);
        convert_result(orcpt_address(&inascii), true)
    }

    #[pyfn(m, "dsn_mail_params")]
    fn py_dsn_mail_params(py2: Python, input: Vec<(&str, Option<&str>)>) -> PyResult<(PyObject, PyObject)> {
        dsn_mail_params(input).map(|(parsed, rem)| (parsed.to_object(py2), rem.to_object(py2))).map_err(|e| PyErr::new::<exc::ValueError, _>(e))
    }

    #[pyfn(m, "mail_command")]
    pub fn py_mail_command(input: &PyBytes) -> PyResult<(String, Vec<EsmtpParam>)>
    {
        convert_result(mail_command(input.data()), true)
    }

    #[pyfn(m, "rcpt_command")]
    pub fn py_rcpt_command(input: &PyBytes) -> PyResult<(String, Vec<EsmtpParam>)>
    {
        convert_result(rcpt_command(input.data()), true)
    }

    #[pyfn(m, "validate_address")]
    pub fn py_validate_address(input: &str) -> PyResult<bool>
    {
        Ok(validate_address(&string_to_ascii(input)))
    }

    Ok(())
}
