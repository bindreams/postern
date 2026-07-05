"""https://www.sphinx-doc.org/en/master/usage/configuration.html"""
import tomllib
from datetime import date
from pathlib import Path

project = "Postern"
author = "Anna Zhukova"
with (Path(__file__).parent.parent / "portal" / "pyproject.toml").open("rb") as f:
    release = tomllib.load(f)["project"]["version"]

year = date.today().year
copyright = f"2026, {author}" if year == 2026 else f"2026-{year}, {author}"
html_title = f"{project} {release}"

extensions = [
    "myst_parser",
    "sphinx_design",
    "sphinx_copybutton",
]
# Directives use backtick fences only: the mdformat-myst prek hook escapes
# colon fences, so enabling colon_fence would invite syntax the formatter
# mangles.
myst_heading_anchors = 3

# Legacy pre-refactor pages: excluded (they are not in any toctree) until the
# content tasks migrate and delete them.
exclude_patterns = [
    "_build",
    "mta.md",
    "certs.md",
    "edge.md",
    "gateway.md",
    "frontend.md",
    "rename.md",
]

html_theme = "furo"
