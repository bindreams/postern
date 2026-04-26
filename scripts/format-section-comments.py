#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# [tool.uv]
# dev-dependencies = ["pytest"]
# ///
"""Pre-commit hook: fix section comment formatting in Rust, Python, TOML, and JS/TS files.

Section comments must follow the format:

    // Section name ======...=  (Rust/JS/TS primary, filled with '=' to column 120)
    // Section name ------...-  (Rust/JS/TS secondary, filled with '-' to column 120)
    # Section name =======...=  (Python/TOML primary, filled with '=' to column 120)
    # Section name -------...-  (Python/TOML secondary, filled with '-' to column 120)

Leading whitespace counts toward the column limit.

Also detects section comments broken across two lines by comment reflow:

    // Section name was too long
    // -------------------------

These are merged back into a single correctly-formatted line.
"""

import os
import re
import sys
from typing import NamedTuple

COLUMN_LIMIT = 120

EXTENSION_PREFIX = {".rs": "//", ".py": "#", ".toml": "#", ".js": "//", ".ts": "//", ".jsx": "//", ".tsx": "//"}


class Patterns(NamedTuple):
    section: re.Pattern[str]
    canonical: re.Pattern[str]
    fill_only: re.Pattern[str]
    name_half: re.Pattern[str]


def make_patterns(prefix: str) -> Patterns:
    """Build compiled regexes for the given comment prefix."""
    p = re.escape(prefix)
    return Patterns(
        # Single-line: <prefix> <text> <run of = or ->  (at least 5 fill chars).
        section=re.compile(rf"^(\s*){p}\s+.+\s+([=-])\2{{4,}}\s*$"),
        # Canonical format for extraction: <prefix> <name> <fill>.
        canonical=re.compile(rf"^(\s*){p} (.+?) ([=-])\3{{4,}}\s*$"),
        # Fill-only line: <prefix> <run of = or ->  (at least 5 fill chars, no other text).
        fill_only=re.compile(rf"^(\s*){p}\s+([=-])\2{{4,}}\s*$"),
        # Preceding comment line that could be the name half of a broken section comment.
        name_half=re.compile(rf"^(\s*){p}(?: (.+))?\s*$"),
    )


def is_doc_comment(line: str, prefix: str) -> bool:
    """Check if a line is a doc/special comment that should not be treated as a section name half."""
    stripped = line.lstrip()
    if prefix == "//":
        return stripped.startswith("///") or stripped.startswith("//!")
    if prefix == "#":
        return stripped.startswith("#!") or stripped.startswith("# ///")
    return False


def rebuild(indent: str, name: str, fill_char: str, prefix: str) -> str:
    """Build a canonical section comment line at COLUMN_LIMIT width."""
    line = f"{indent}{prefix} {name} "
    fill_count = COLUMN_LIMIT - len(line)
    if fill_count < 5:
        fill_count = 5
    return line + fill_char * fill_count


def process_lines(lines: list[str], patterns: Patterns, prefix: str) -> tuple[list[str], bool]:
    """Fix section comments in a list of lines. Returns (new_lines, changed)."""
    changed = False
    skip_next = False
    new_lines: list[str] = []

    for i, raw_line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        line = raw_line.rstrip("\r\n")

        # Case 1: fill-only line — check if previous line is the name half.
        fill_m = patterns.fill_only.match(line)
        if fill_m and new_lines:
            prev_line = new_lines[-1].rstrip("\r\n")
            name_m = patterns.name_half.match(prev_line)
            if (
                name_m and not patterns.section.match(prev_line) and not is_doc_comment(prev_line, prefix)
                and name_m.group(2)  # has actual text after prefix
            ):
                indent = name_m.group(1)
                name = name_m.group(2).rstrip()
                fill_char = fill_m.group(2)
                fixed = rebuild(indent, name, fill_char, prefix)
                new_lines[-1] = fixed + "\n"
                changed = True
                continue

        # Case 2: single-line section comment with wrong format/length.
        sec_m = patterns.section.match(line)
        if sec_m:
            can_m = patterns.canonical.match(line)
            if can_m:
                indent, name, fill_char = can_m.group(1), can_m.group(2), can_m.group(3)
                fixed = rebuild(indent, name, fill_char, prefix)
                if fixed != line:
                    new_lines.append(fixed + "\n")
                    changed = True
                    continue

        # Case 3: two-line break where name is on current line and fill is on next.
        if i + 1 < len(lines):
            next_line = lines[i + 1].rstrip("\r\n")
            fill_m2 = patterns.fill_only.match(next_line)
            if fill_m2:
                name_m2 = patterns.name_half.match(line)
                if (
                    name_m2 and not patterns.section.match(line) and not is_doc_comment(line, prefix)
                    and name_m2.group(2)
                ):
                    indent = name_m2.group(1)
                    name = name_m2.group(2).rstrip()
                    fill_char = fill_m2.group(2)
                    fixed = rebuild(indent, name, fill_char, prefix)
                    new_lines.append(fixed + "\n")
                    skip_next = True
                    changed = True
                    continue

        new_lines.append(raw_line)

    return new_lines, changed


def process_file(path: str) -> bool:
    """Process one file. Returns True if the file was modified."""
    ext = os.path.splitext(path)[1]
    prefix = EXTENSION_PREFIX.get(ext)
    if prefix is None:
        return False

    with open(path, encoding="utf-8", newline="") as f:
        lines = f.readlines()

    patterns = make_patterns(prefix)
    new_lines, changed = process_lines(lines, patterns, prefix)

    if changed:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.writelines(new_lines)

    return changed


def main():
    any_changed = False
    for path in sys.argv[1:]:
        if process_file(path):
            print(f"Fixed section comments in {path}", file=sys.stderr)
            any_changed = True

    if any_changed:
        return 1  # Signal to pre-commit that changes were made.


if __name__ == "__main__":
    sys.exit(main())

# Tests ================================================================================================================
# run manually with `uv run --with pytest pytest scripts/format-section-comments.py`


def _lines(text: str) -> list[str]:
    """Split text into lines preserving newlines, like file.readlines()."""
    return text.splitlines(keepends=True)


def _fix(text: str, prefix: str) -> str:
    patterns = make_patterns(prefix)
    result, _ = process_lines(_lines(text), patterns, prefix)
    return "".join(result)


def _changed(text: str, prefix: str) -> bool:
    patterns = make_patterns(prefix)
    _, changed = process_lines(_lines(text), patterns, prefix)
    return changed


# Rust tests -----------------------------------------------------------------------------------------------------------

_RUST_CORRECT_PRIMARY = "// CLI " + "=" * 113
_RUST_CORRECT_SECONDARY = "    // Helpers " + "-" * (120 - len("    // Helpers "))


def test_rust_correct_comment_unchanged():
    assert not _changed(_RUST_CORRECT_PRIMARY, "//")
    assert not _changed(_RUST_CORRECT_SECONDARY, "//")


def test_rust_too_short_padded():
    short = "// CLI " + "=" * 30
    result = _fix(short, "//")
    assert result.rstrip() == _RUST_CORRECT_PRIMARY
    assert len(result.rstrip()) == 120


def test_rust_too_long_trimmed():
    long = "// CLI " + "=" * 200
    result = _fix(long, "//")
    assert result.rstrip() == _RUST_CORRECT_PRIMARY


def test_rust_indented_comment():
    indented = "    // Helpers " + "-" * 50
    result = _fix(indented, "//")
    assert result.rstrip() == _RUST_CORRECT_SECONDARY
    assert len(result.rstrip()) == 120


def test_rust_reflow_name_then_fill():
    text = "// Section name was reflowed\n// -------------------------\n"
    result = _fix(text, "//")
    assert result.count("\n") == 1
    line = result.rstrip()
    assert line.startswith("// Section name was reflowed -")
    assert len(line) == 120


def test_rust_reflow_fill_after_previous_output():
    text = "fn foo() {}\n// Broken section\n// ==========\nfn bar() {}\n"
    result = _fix(text, "//")
    lines = result.splitlines()
    assert lines[0] == "fn foo() {}"
    assert lines[1].startswith("// Broken section =")
    assert len(lines[1]) == 120
    assert lines[2] == "fn bar() {}"


def test_rust_doc_comment_not_touched():
    text = "/// This is a doc comment\n// ==========\n"
    assert not _changed(text, "//")


def test_rust_module_doc_comment_not_touched():
    text = "//! Module doc\n// ==========\n"
    assert not _changed(text, "//")


def test_rust_plain_comment_not_touched():
    text = "// This is a regular comment, not a section\nfn foo() {}\n"
    assert not _changed(text, "//")


def test_rust_code_not_touched():
    text = 'fn main() {\n    println!("hello");\n}\n'
    assert not _changed(text, "//")


def test_rust_indented_reflow():
    text = "    // Indented section\n    // -------------------\n"
    result = _fix(text, "//")
    assert result.count("\n") == 1
    line = result.rstrip()
    assert line.startswith("    // Indented section -")
    assert len(line) == 120


def test_rust_indented_reflow_equals():
    text = "        // Deep nesting\n        // ============\n"
    result = _fix(text, "//")
    assert result.count("\n") == 1
    line = result.rstrip()
    assert line.startswith("        // Deep nesting =")
    assert len(line) == 120


def test_rust_indented_correct_unchanged():
    indent = "        "
    name = "Deep nesting"
    line = f"{indent}// {name} " + "=" * (120 - len(f"{indent}// {name} "))
    assert len(line) == 120
    assert not _changed(line, "//")


def test_rust_very_long_name_gets_minimum_fill():
    name = "A" * 115
    text = f"// {name} =====\n"
    result = _fix(text, "//")
    line = result.rstrip()
    assert line.endswith("=" * 5)
    assert f"// {name} " in line


# Python tests ---------------------------------------------------------------------------------------------------------

_PY_CORRECT_PRIMARY = "# CLI " + "=" * 114
_PY_CORRECT_SECONDARY = "    # Helpers " + "-" * (120 - len("    # Helpers "))


def test_python_correct_comment_unchanged():
    assert not _changed(_PY_CORRECT_PRIMARY, "#")
    assert not _changed(_PY_CORRECT_SECONDARY, "#")


def test_python_too_short_padded():
    short = "# CLI " + "=" * 30
    result = _fix(short, "#")
    assert result.rstrip() == _PY_CORRECT_PRIMARY
    assert len(result.rstrip()) == 120


def test_python_too_long_trimmed():
    long = "# CLI " + "=" * 200
    result = _fix(long, "#")
    assert result.rstrip() == _PY_CORRECT_PRIMARY


def test_python_indented_comment():
    indented = "    # Helpers " + "-" * 50
    result = _fix(indented, "#")
    assert result.rstrip() == _PY_CORRECT_SECONDARY
    assert len(result.rstrip()) == 120


def test_python_reflow_name_then_fill():
    text = "# Section name was reflowed\n# -------------------------\n"
    result = _fix(text, "#")
    assert result.count("\n") == 1
    line = result.rstrip()
    assert line.startswith("# Section name was reflowed -")
    assert len(line) == 120


def test_python_reflow_fill_after_previous_output():
    text = "def foo(): pass\n# Broken section\n# ==========\ndef bar(): pass\n"
    result = _fix(text, "#")
    lines = result.splitlines()
    assert lines[0] == "def foo(): pass"
    assert lines[1].startswith("# Broken section =")
    assert len(lines[1]) == 120
    assert lines[2] == "def bar(): pass"


def test_python_shebang_not_touched():
    text = "#!/usr/bin/env python3\n# ==========\n"
    assert not _changed(text, "#")


def test_python_pep723_marker_not_touched():
    text = "# /// script\n# ==========\n"
    assert not _changed(text, "#")


def test_python_plain_comment_not_touched():
    text = "# This is a regular comment, not a section\ndef foo(): pass\n"
    assert not _changed(text, "#")


def test_python_code_not_touched():
    text = 'def main():\n    print("hello")\n'
    assert not _changed(text, "#")


def test_python_indented_reflow():
    text = "    # Indented section\n    # -------------------\n"
    result = _fix(text, "#")
    assert result.count("\n") == 1
    line = result.rstrip()
    assert line.startswith("    # Indented section -")
    assert len(line) == 120


def test_python_indented_correct_unchanged():
    indent = "        "
    name = "Deep nesting"
    line = f"{indent}# {name} " + "=" * (120 - len(f"{indent}# {name} "))
    assert len(line) == 120
    assert not _changed(line, "#")


def test_python_very_long_name_gets_minimum_fill():
    name = "A" * 115
    text = f"# {name} =====\n"
    result = _fix(text, "#")
    line = result.rstrip()
    assert line.endswith("=" * 5)
    assert f"# {name} " in line


# File dispatch tests --------------------------------------------------------------------------------------------------


def test_unknown_extension_skipped(tmp_path):
    p = tmp_path / "test.txt"
    p.write_text("// Short =====\n")
    assert not process_file(str(p))
    assert p.read_text() == "// Short =====\n"


def test_process_file_rs(tmp_path):
    p = tmp_path / "test.rs"
    p.write_text("// CLI " + "=" * 30 + "\n")
    assert process_file(str(p))
    assert len(p.read_text().rstrip()) == 120


def test_process_file_py(tmp_path):
    p = tmp_path / "test.py"
    p.write_text("# CLI " + "=" * 30 + "\n")
    assert process_file(str(p))
    assert len(p.read_text().rstrip()) == 120


# JS/TS tests ----------------------------------------------------------------------------------------------------------

_JS_CORRECT_PRIMARY = "// State management " + "=" * (120 - len("// State management "))
_JS_CORRECT_SECONDARY = "  // Helpers " + "-" * (120 - len("  // Helpers "))


def test_js_correct_comment_unchanged():
    assert not _changed(_JS_CORRECT_PRIMARY, "//")
    assert not _changed(_JS_CORRECT_SECONDARY, "//")


def test_js_too_short_padded():
    short = "// State management " + "=" * 30
    result = _fix(short, "//")
    assert result.rstrip() == _JS_CORRECT_PRIMARY
    assert len(result.rstrip()) == 120


def test_js_reflow_name_then_fill():
    text = "// Config management\n// -------------------------\n"
    result = _fix(text, "//")
    assert result.count("\n") == 1
    line = result.rstrip()
    assert line.startswith("// Config management -")
    assert len(line) == 120


def test_process_file_js(tmp_path):
    p = tmp_path / "test.js"
    p.write_text("// State " + "=" * 30 + "\n")
    assert process_file(str(p))
    assert len(p.read_text().rstrip()) == 120


def test_process_file_ts(tmp_path):
    p = tmp_path / "test.ts"
    p.write_text("// State " + "=" * 30 + "\n")
    assert process_file(str(p))
    assert len(p.read_text().rstrip()) == 120


def test_process_file_jsx(tmp_path):
    p = tmp_path / "test.jsx"
    p.write_text("// State " + "=" * 30 + "\n")
    assert process_file(str(p))
    assert len(p.read_text().rstrip()) == 120


def test_process_file_tsx(tmp_path):
    p = tmp_path / "test.tsx"
    p.write_text("// State " + "=" * 30 + "\n")
    assert process_file(str(p))
    assert len(p.read_text().rstrip()) == 120


# TOML tests -----------------------------------------------------------------------------------------------------------


def test_process_file_toml(tmp_path):
    p = tmp_path / "test.toml"
    p.write_text("# Local hooks " + "=" * 30 + "\n")
    assert process_file(str(p))
    assert len(p.read_text().rstrip()) == 120


def test_toml_correct_comment_unchanged():
    line = "# Local hooks " + "=" * (120 - len("# Local hooks "))
    assert not _changed(line, "#")


def test_toml_reflow():
    text = "# External hooks\n# -------------------------\n"
    result = _fix(text, "#")
    assert result.count("\n") == 1
    line = result.rstrip()
    assert line.startswith("# External hooks -")
    assert len(line) == 120
