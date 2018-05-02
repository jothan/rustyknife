use pyo3::{self, Python, PyResult, PyModule, PyString, PyBytes};
use pyo3::py::modinit as pymodinit;

#[pymodinit(rustyknife)]
fn init_module(py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "from_")]
    fn run(from: &PyString) -> PyResult<String> {
        Ok("Hello Python!".to_string())
    }

    Ok(())
}
