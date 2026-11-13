"""Build-time import check for the mta and provisioner images (issue #266).

Run in the image's final stage as the runtime user, with the same bare `python3` the ENTRYPOINT
resolves from PATH. A Python minor that apk and the COPY targets disagree on builds fine and only
fails at container start.

    image-import-check.py ENTRYPOINT PACKAGE...

Imports every submodule of each PACKAGE, so a module added later is covered with no list to edit, and
runs ENTRYPOINT as a non-`__main__` module (its top-level imports). Then imports every module that
ENTRYPOINT and the walked package files import anywhere, including inside functions. Imports under
`try/except ImportError`, `if TYPE_CHECKING` and platform/version guards are optional by construction
and are skipped. Stdlib only: the image has no pip.
"""
import ast
import importlib
import pkgutil
import runpy
import sys
from types import ModuleType
from typing import NoReturn

# Failure and import primitives ========================================================================================


def _fail(what: str, exc: BaseException) -> NoReturn:
    print(f"image-import-check: {what}: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)


def _import(name: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except BaseException as exc:  # noqa: BLE001 -- SystemExit at import time is a failure too
        _fail(f"import {name}", exc)


# Guard detection ======================================================================================================

_IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
_PLATFORM_NAMES = {"sys", "os", "platform"}


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(t, ast.Name) and t.id in _IMPORT_ERRORS for t in types)


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name)
            and test.id == "TYPE_CHECKING") or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _is_platform_guard(test: ast.expr) -> bool:
    return any(isinstance(n, ast.Name) and n.id in _PLATFORM_NAMES for n in ast.walk(test))


# Required imports of one source file ==================================================================================


def _required_imports(tree: ast.AST) -> list[ast.Import | ast.ImportFrom]:
    found: list[ast.Import | ast.ImportFrom] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            found.append(node)
        elif isinstance(node, ast.Try):
            if not any(_catches_import_error(h) for h in node.handlers):
                for child in node.body:
                    visit(child)
            for child in (*node.handlers, *node.orelse, *node.finalbody):
                visit(child)
        elif isinstance(node, ast.If) and _is_type_checking(node.test):
            for child in node.orelse:
                visit(child)
        elif isinstance(node, ast.If) and _is_platform_guard(node.test):
            pass
        else:
            for child in ast.iter_child_nodes(node):
                visit(child)

    visit(tree)
    return found


def _import_required(path: str) -> None:
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)
    for node in _required_imports(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _import(alias.name)
        elif node.level == 0 and node.module:
            module = _import(node.module)
            for alias in node.names:
                if alias.name != "*" and not hasattr(module, alias.name):
                    _import(f"{node.module}.{alias.name}")


# Package walk =========================================================================================================


def _source_file(module: ModuleType) -> list[str]:
    origin = module.__file__
    return [origin] if origin and origin.endswith(".py") else []


def _import_package_tree(package: str) -> list[str]:
    """Import PACKAGE and every submodule; return their source files."""
    root = _import(package)
    files = _source_file(root)
    path = getattr(root, "__path__", None)
    if path is None:
        return files
    for info in pkgutil.walk_packages(path, prefix=f"{package}.", onerror=_import):
        files += _source_file(_import(info.name))
    return files


# Entry point ==========================================================================================================


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        sys.exit(f"usage: {argv[0]} ENTRYPOINT PACKAGE...")
    entrypoint, packages = argv[1], argv[2:]
    sources = [entrypoint]
    for package in packages:
        sources += _import_package_tree(package)
    try:
        runpy.run_path(entrypoint, run_name="entrypoint_import_check")
    except BaseException as exc:  # noqa: BLE001 -- SystemExit from die() at import time is a failure too
        _fail(f"run {entrypoint}", exc)
    for source in sources:
        _import_required(source)


if __name__ == "__main__":
    main(sys.argv)
