"""Negative fixture for the docs reference gate.

This project must FAIL to build under `sphinx-build -W`: index.md links to a
missing page and orphan.md is in no toctree. CI asserts both warnings appear,
so a myst/sphinx upgrade that stops warning is caught instead of silently
disarming the real docs build.

Mirror docs/conf.py's link-resolution-relevant settings.
"""
extensions = ["myst_parser", "sphinx_design", "sphinx_copybutton"]
myst_heading_anchors = 3
exclude_patterns = ["_build"]
