import os
import platform
import re
import subprocess
import sys

from Cython.Build import cythonize
from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext as _build_ext

WINDOWS = platform.system() == "Windows"
SETUP_MODULE_NAME = "voucher"
SETUP_EXTENSION_LIBS = ["voucher_if"]
LOCAL_INCLUDE = os.path.join("local", "include")
LOCAL_LIB = os.path.join("local", "lib")
STATIC_LIB = os.path.join(LOCAL_LIB, "libvoucher_if.a")


def from_env(var):
    envsep = ";" if WINDOWS else ":"
    raw = os.environ.get(var)
    if not raw:
        return []
    return [part for part in raw.split(envsep) if part]


class build_ext(_build_ext):
    """Link against the cargo static lib. Build it if this tree does not have it yet.

    `make dist` already runs `make local` first. This is the fallback for
    `pip install .` so setup.py does not shell out to `make dist` (that
    re-entered `python setup.py` and tripped the deprecation warning).
    """

    def run(self):
        if not WINDOWS and not os.path.exists(STATIC_LIB):
            subprocess.run(["make", "local"], check=True)
        super().run()


def _get_version():
    pattern = re.compile(r'^__version__ = ["]([.\w]+?)["]')
    init_py = os.path.join("src", SETUP_MODULE_NAME, "__init__.py")
    with open(init_py) as handle:
        for line in handle:
            match = pattern.match(line)
            if match:
                return match.group(1)
    raise RuntimeError(f"__version__ not found in {init_py}")


def extensions(coverage=False):
    libraries = (
        ["AdvAPI32", "mbedTLS"] if WINDOWS else list(SETUP_EXTENSION_LIBS)
    )
    library_dirs = from_env("LIBPATH" if WINDOWS else "LIBRARY_PATH")
    if not WINDOWS and LOCAL_LIB not in library_dirs:
        library_dirs.append(LOCAL_LIB)

    include_dirs = [LOCAL_INCLUDE] if os.path.isdir(LOCAL_INCLUDE) else []
    directives = {"language_level": "3str"}
    define_macros = []
    if coverage:
        directives["linetrace"] = True
        define_macros = [("CYTHON_TRACE", "1"), ("CYTHON_TRACE_NOGIL", "1")]

    found = []
    for dirpath, _, filenames in os.walk("src"):
        for filename in filenames:
            root, ext = os.path.splitext(filename)
            if ext != ".pyx":
                continue
            mod = ".".join(dirpath.split(os.sep)[1:] + [root])
            found.append(
                Extension(
                    mod,
                    sources=[os.path.join(dirpath, filename)],
                    include_dirs=include_dirs,
                    library_dirs=library_dirs,
                    libraries=libraries,
                    define_macros=define_macros,
                )
            )
    if not found:
        raise RuntimeError("no .pyx extensions under src/")
    return cythonize(found, compiler_directives=directives)


if "--with-coverage" in sys.argv:
    sys.argv.remove("--with-coverage")
    COVERAGE = True
else:
    COVERAGE = False

VERSION = _get_version()

setup(
    name=f"python-{SETUP_MODULE_NAME}",
    version=VERSION,
    cmdclass={"build_ext": build_ext},
    ext_modules=extensions(COVERAGE),
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.12",
    install_requires=["certifi"],
)
