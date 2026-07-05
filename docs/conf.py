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
# No colon_fence: the mdformat-myst prek hook escapes colon fences, so the
# docs use backtick-fenced directives exclusively.
myst_enable_extensions = []
myst_heading_anchors = 3

exclude_patterns = ["_build"]

html_theme = "furo"
