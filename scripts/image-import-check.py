"""Build-time import check for the mta and provisioner images.

Run in the image's final stage as the runtime user, with the bare `python3` the ENTRYPOINT uses.
A minor that apk and the COPY targets disagree on builds fine and only fails at container start.

    image-import-check.py PYTHON_MINOR ENTRYPOINT --first-party PACKAGE... --third-party MODULE...

1. The running interpreter is PYTHON_MINOR (the Dockerfile ARG the COPY targets are built from).
2. Every PACKAGE and each of its submodules imports, and lives under
   /usr/lib/python<PYTHON_MINOR>/site-packages, where the Dockerfile copied it. A module added later
   is covered with no list to edit. A directory that holds .py files but has no `__init__.py` (at
   any level) is a failure: the package walk would skip it, leaving its modules unchecked.
3. Every third-party MODULE (apk- or pip-installed, used by the image's code) imports from the same
   site-packages.
4. ENTRYPOINT runs as a non-`__main__` module, which executes its top-level imports.

Stdlib only: the image has no pip.
"""
import argparse
import importlib
import os
import pkgutil
import runpy
import sys
from types import ModuleType
from typing import NoReturn

# Failure and import primitives ========================================================================================


def _fail(what: str, exc: BaseException | str) -> NoReturn:
    detail = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"
    print(f"image-import-check: {what}: {detail}", file=sys.stderr)
    sys.exit(1)


def _import(name: str, site_packages: str) -> ModuleType:
    """Import NAME and require its file to be under SITE_PACKAGES."""
    try:
        module = importlib.import_module(name)
    except BaseException as exc:  # noqa: BLE001 -- SystemExit at import time is a failure too
        _fail(f"import {name}", exc)
    origin = module.__file__
    if origin is None or not origin.startswith(site_packages + "/"):
        _fail(f"import {name}", f"loaded from {origin}, expected under {site_packages}")
    return module


# Package walk =========================================================================================================


def _import_package_tree(package: str, site_packages: str) -> None:
    root = _import(package, site_packages)
    path = getattr(root, "__path__", None)
    if path is None:
        return

    def on_error(name: str) -> None:
        _fail(f"import {name}", sys.exc_info()[1] or "walk_packages reported an import error")

    for info in pkgutil.walk_packages(path, prefix=f"{package}.", onerror=on_error):
        _import(info.name, site_packages)
    for entry in path:
        _require_init_files(package, entry)


def _require_init_files(package: str, entry: str) -> None:
    """Fail on a directory under ENTRY with .py files but no `__init__.py` at it or any level above it."""
    for dirpath, _, filenames in os.walk(entry):
        if not any(name.endswith(".py") for name in filenames):
            continue
        current = entry
        for part in os.path.relpath(dirpath, entry).split(os.sep):
            if part != ".":
                current = os.path.join(current, part)
            if not os.path.isfile(os.path.join(current, "__init__.py")):
                _fail(f"walk {package}", f"{current} holds modules but has no __init__.py, so they are not checked")


# Entry point ==========================================================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("python_minor")
    parser.add_argument("entrypoint")
    parser.add_argument("--first-party", nargs="+", default=[])
    parser.add_argument("--third-party", nargs="+", default=[])
    args = parser.parse_args()

    actual = f"{sys.version_info.major}.{sys.version_info.minor}"
    if actual != args.python_minor:
        _fail("python version", f"interpreter is {actual}, image pins {args.python_minor}")
    site_packages = f"/usr/lib/python{args.python_minor}/site-packages"

    for package in args.first_party:
        _import_package_tree(package, site_packages)
    for module in args.third_party:
        _import(module, site_packages)
    try:
        runpy.run_path(args.entrypoint, run_name="entrypoint_import_check")
    except BaseException as exc:  # noqa: BLE001 -- SystemExit from die() at import time is a failure too
        _fail(f"run {args.entrypoint}", exc)


if __name__ == "__main__":
    main()
