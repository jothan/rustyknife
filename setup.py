from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(name='rustyknife',
      version='0.1.1',
      rust_extensions=[RustExtension('rustyknife',
                                     'Cargo.toml', binding=Binding.PyO3)],
      zip_safe=False
)
