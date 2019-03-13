use std::fmt::Debug;
use std::fs::File;

use crate::rfc2231::{content_type, content_disposition, content_transfer_encoding};
use crate::rfc3461::{orcpt_address, dsn_mail_params, DSNMailParams, DSNRet};
use crate::rfc5321::{EsmtpParam, mail_command, rcpt_command, validate_address, Path, ReversePath};
use crate::rfc5322::{Address, Mailbox, Group, from, sender, reply_to, unstructured};
use crate::headersection::{HeaderField, header_section};
use crate::xforward::{XforwardParam, xforward_params};
use crate::util::{KResult, string_to_ascii};

use memmap::Mmap;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple, PyDict};
use pyo3::types::exceptions as exc;

macro_rules! intopyobject {
    ( $e:ident ) => {
        impl IntoPyObject for $e {
            fn into_object(self, py: Python) -> PyObject {
                self.to_object(py)
            }
        }
    }
}

intopyobject!(Address);
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

intopyobject!(XforwardParam);
impl ToPyObject for XforwardParam {
    fn to_object(&self, py: Python) -> PyObject {
        PyTuple::new(py, &[self.0.to_object(py),
                           self.1.to_object(py)]).into_object(py)
    }
}

intopyobject!(EsmtpParam);
impl ToPyObject for EsmtpParam {
    fn to_object(&self, py: Python) -> PyObject {
        PyTuple::new(py, &[self.0.to_object(py),
                           self.1.to_object(py)]).into_object(py)
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

intopyobject!(Path);
impl ToPyObject for Path {
    fn to_object(&self, py: Python) -> PyObject {
        match self {
            Path::Path(p) => p.to_object(py),
            Path::PostMaster => "postmaster".to_object(py),
        }
    }
}

intopyobject!(ReversePath);
impl ToPyObject for ReversePath {
    fn to_object(&self, py: Python) -> PyObject {
        match self {
            ReversePath::Path(p) => p.to_object(py),
            ReversePath::Null => "".to_object(py),
        }
    }
}

fn convert_result<O, E: Debug> (input: KResult<&[u8], O, E>, match_all: bool) -> PyResult<O> {
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

fn fix_bare_cr(input: &[u8]) -> Vec<u8> {
    // Remove bare CR and make sure every LF is preceeded by CR.
    input.iter().cloned().filter(|c| *c != b'\r')
        .fold(Vec::with_capacity(input.len()), |mut acc, c| {
            match c {
                b'\n' => acc.extend_from_slice(b"\r\n"),
                _ => acc.push(c),
            }
            acc
        })
}

#[pymodule]
fn rustyknife(_py: Python, m: &PyModule) -> PyResult<()> {
    /// from_(input)
    #[pyfn(m, "from_")]
    fn py_from(input: &PyBytes) -> PyResult<Vec<Address>> {
        convert_result(from(input.as_bytes()), true)
    }

    /// sender(input)
    #[pyfn(m, "sender")]
    fn py_sender(input: &PyBytes) -> PyResult<Address> {
        convert_result(sender(input.as_bytes()), true)
    }

    /// reply_to(input)
    #[pyfn(m, "reply_to")]
    fn py_reply_to(input: &PyBytes) -> PyResult<Vec<Address>> {
        convert_result(reply_to(input.as_bytes()), true)
    }

    /// header_section(input) -> ([headers...], end of headers position)
    ///
    /// :param input: Input string.
    /// :type input: bytes
    /// :return: A list of separated header (name, value) tuples with
    ///  the exact byte position of the end of headers.
    /// :rtype: list of byte string tuples
    #[pyfn(m, "header_section")]
    fn py_header_section(py2: Python, input: &PyBytes) -> PyResult<PyObject> {
        header_section_slice(py2, input.as_bytes())
    }

    /// header_section_file(fname) -> ([headers...], end of headers position)
    ///
    /// :param fname: File name to read.
    /// :type fname: str
    /// :return: Same as :meth:`header_section`
    #[pyfn(m, "header_section_file")]
    fn py_header_section_file(py2: Python, fname: &str) -> PyResult<PyObject> {
        let file = File::open(fname)?;
        let fmap = unsafe { Mmap::map(&file)? };

        header_section_slice(py2, &fmap)
    }

    /// xforward_params(input)
    #[pyfn(m, "xforward_params")]
    fn py_xforward_params(input: &PyBytes) -> PyResult<Vec<XforwardParam>> {
        convert_result(xforward_params(input.as_bytes()), true)
    }

    /// orcpt_address(input)
    #[pyfn(m, "orcpt_address")]
    fn py_orcpt_address(input: &str) -> PyResult<(String, String)> {
        let inascii = string_to_ascii(&input);
        convert_result(orcpt_address(&inascii), true)
    }

    /// dsn_mail_params(input)
    #[pyfn(m, "dsn_mail_params")]
    fn py_dsn_mail_params(py2: Python, input: Vec<(&str, Option<&str>)>) -> PyResult<(PyObject, PyObject)> {
        dsn_mail_params(&input).map(|(parsed, rem)| (parsed.to_object(py2), rem.to_object(py2))).map_err(PyErr::new::<exc::ValueError, _>)
    }

    /// mail_command(input)
    ///
    /// :param input: Full SMTP MAIL command
    ///
    ///  b'MAIL FROM:<user@example.org> BODY=7BIT'
    /// :type input: bytes
    /// :return: (address, [(param, param_value), ...])
    #[pyfn(m, "mail_command")]
    pub fn py_mail_command(input: &PyBytes) -> PyResult<(ReversePath, Vec<EsmtpParam>)>
    {
        convert_result(mail_command(input.as_bytes()), true)
    }

    /// rcpt_command(input)
    ///
    /// :param input: Full SMTP RCPT command
    ///
    ///  b'RCPT TO:<user@example.org> ORCPT=rfc822;user@example.org'
    /// :type input: bytes
    /// :return: (address, [(param, param_value), ...])
    #[pyfn(m, "rcpt_command")]
    pub fn py_rcpt_command(input: &PyBytes) -> PyResult<(Path, Vec<EsmtpParam>)>
    {
        convert_result(rcpt_command(input.as_bytes()), true)
    }

    /// validate_address(address)
    ///
    /// :param address: Non-empty address without <> brackets.
    /// :type address: str
    /// :rtype: bool
    #[pyfn(m, "validate_address")]
    pub fn py_validate_address(input: &str) -> PyResult<bool>
    {
        Ok(validate_address(&string_to_ascii(input)))
    }

    /// unstructured(input)
    ///
    /// Decode an unstructured email header.
    ///
    /// Useful for converting subject lines.
    ///
    /// :param input: Input string
    /// :type input: bytes
    /// :return: Decoded header
    /// :rtype: str
    #[pyfn(m, "unstructured")]
    fn py_unstructured(input: &PyBytes) -> PyResult<String> {
        convert_result(unstructured(input.as_bytes()), true)
    }

    /// content_type(input, all=False)
    #[pyfn(m, "content_type", input, all=false)]
    fn py_content_type(input: &PyBytes, all: bool) -> PyResult<(String, Vec<(String, String)>)> {
        // FIXME: Figure out how to better handle a bare LF in
        // quoted-string without duplicating the rest of the RFC5322
        // syntax
        convert_result(content_type(&fix_bare_cr(input.as_bytes())), all)
    }

    /// content_disposition(input, all=False)
    #[pyfn(m, "content_disposition", input, all=false)]
    fn py_content_disposition(input: &PyBytes, all: bool) -> PyResult<(String, Vec<(String, String)>)> {
        convert_result(content_disposition(&fix_bare_cr(input.as_bytes())), all)
    }

    /// content_transfer_encoding(input, all=False)
    ///
    /// Parse a MIME Content-Transfer-Encoding header.
    ///
    /// Standard encodings such as 7bit, 8bit are accepted. Extended
    /// encodings starting with a 'x-' prefix are also accepted.
    ///
    /// :param input: Input string.
    /// :type input: bytes
    /// :return: Validated Content-Transfer-Encoding
    /// :rtype: str
    ///
    #[pyfn(m, "content_transfer_encoding", input, all=false)]
    fn py_content_transfer_encoding(input: &PyBytes, all: bool) -> PyResult<String> {
        convert_result(content_transfer_encoding(&fix_bare_cr(input.as_bytes())), all)
    }

    Ok(())
}
