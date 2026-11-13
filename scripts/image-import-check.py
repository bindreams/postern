"""Build-time import check for the mta and provisioner images (issue #266).

Run in the image's final stage with the same bare `python3` the ENTRYPOINT resolves from PATH. A Python
minor that apk and the COPY targets disagree on builds fine and only fails at container start.

    image-import-check.py ENTRYPOINT PACKAGE...

Imports every submodule of each PACKAGE, so a module added later is covered with no list to edit, runs
ENTRYPOINT as a non-`__main__` module (its top-level imports), and imports every module the entrypoint
imports anywhere, including inside functions. Stdlib only: the image has no pip.
"""
import ast
import importlib
import pkgutil
import runpy
import sys


def _fail(what: str, exc: BaseException) -> None:
    print(f"image-import-check: {what}: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)


def _import(name: str) -> object:
    try:
        return importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 -- any failure is the finding
        _fail(f"import {name}", exc)
        raise


def _import_package_tree(package: str) -> None:
    root = _import(package)
    path = getattr(root, "__path__", None)
    if path is None:
        return
    for info in pkgutil.walk_packages(path, prefix=f"{package}.", onerror=lambda name: _import(name)):
        _import(info.name)


def _import_entrypoint_imports(entrypoint: str) -> None:
    with open(entrypoint, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=entrypoint)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _import(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            module = _import(node.module)
            for alias in node.names:
                if alias.name != "*" and not hasattr(module, alias.name):
                    _import(f"{node.module}.{alias.name}")


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        sys.exit(f"usage: {argv[0]} ENTRYPOINT PACKAGE...")
    entrypoint, packages = argv[1], argv[2:]
    for package in packages:
        _import_package_tree(package)
    try:
        runpy.run_path(entrypoint, run_name="entrypoint_import_check")
    except BaseException as exc:  # noqa: BLE001 -- SystemExit from die() at import time is a failure too
        _fail(f"run {entrypoint}", exc)
    _import_entrypoint_imports(entrypoint)


if __name__ == "__main__":
    main(sys.argv)
