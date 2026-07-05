"""Content gates binding docs/ to the code it documents.

These gates catch enumerable drift (names, paths, defaults) and act as
deletion tripwires for load-bearing caveats -- they detect a dropped caveat,
not a softened one.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).parents[2]
DOCS_DIR = REPO_ROOT / "docs"

REPO_URL = re.compile(r"https://github\.com/bindreams/postern(/[^)\s`\"'<>]*)?")
SOURCE_LINK = re.compile(r"^/(?:blob|tree)/main/([^)\s`\"'<>,;#]+)(#[^)\s`\"'<>]*)?$")
# Issue/PR/release targets are deliberately NOT existence-checked: that would
# need network access, which this unit gate must not have.
OTHER_OK_LINK = re.compile(r"^/(?:issues|pull|releases)(/|$)")

# Deletion tripwires: distinctive caveat PHRASES (verified verbatim against
# the page at write time), not bare identifiers -- an identifier appears in
# config tables regardless of whether its caveat survived.
MUST_KEEP = {
    "deployment/email.md": ["milter_default_action = tempfail", "silently tampered"],
    "deployment/certificates.md": ["symlink-flip", "one-shot bypass"],
    "deployment/configuration.md": ["cookie `max_age`"],
    "deployment/gateway.md": ["forge a PROXY header", "broken header"],
    "deployment/edge.md": ["Authenticated Origin Pull", "origin-pull CA"],
    "operations/rename.md": ["_domainkey", "docker compose down"],
    "operations/index.md": ["postern reconcile"],
}

# Tripwires that mirror a machine value: the phrase must appear on the page
# AND in its source of truth, so a code-side rename reds the gate instead of
# letting the doc rot. Keep MUST_KEEP prose entries few; anything with a
# machine-readable source belongs here instead.
MUST_KEEP_CODE = [
    # (docs page, literal, source file that owns the literal)
    ("deployment/email.md", "SMTP_HOST=mta-submit", "example.env"),
    ("deployment/email.md", "milter_default_action = tempfail", "mta/etc/main.cf.tmpl"),
    ("development/testing.md", "e2e_mta_real", "portal/pyproject.toml"),
    ("development/testing.md", "e2e_mta_outbound", "portal/pyproject.toml"),
    ("development/architecture.md", "default-src", "nginx/etc/nginx.conf.tmpl"),
    ("operations/index.md", ".reconcile-now", "portal/src/postern/reconciler.py"),
]

# Escape hatch for vars legitimately documented in configuration.md that are
# neither Settings fields nor defined in example.env/compose. Keep empty
# unless a page genuinely needs one; provider credentials belong in
# email.md's provider table, which this gate never parses.
DOC_ONLY_VARS: set[str] = set()


def _external_env_vars() -> set[str]:
    """Env vars defined outside portal Settings: example.env assignments
    (commented ones included -- they document optional vars) and ${VAR}
    interpolations in compose files. Deliberately NOT a free-text
    uppercase-token scan, which would allowlist prose words and capability
    names and silently false-pass phantom documented vars."""
    env_text = (REPO_ROOT / "example.env").read_text(encoding="utf-8")
    found = set(re.findall(r"^\s*#?\s*([A-Z][A-Z0-9_]+)=", env_text, flags=re.M))
    for compose in sorted(REPO_ROOT.glob("compose*.yaml")):
        found |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]+)[:}?-]", compose.read_text(encoding="utf-8")))
    assert found, "no env vars found in example.env/compose files -- sources moved?"
    return found


def _docs_md() -> list[Path]:
    files = sorted(DOCS_DIR.rglob("*.md"))
    assert files, "docs tree is empty -- content gates would pass vacuously"
    return files


def test_github_links_resolve():
    """Repo links: sanctioned blob/tree@main shape, existing path, no line anchors.

    Fails closed: any github.com/bindreams/postern URL that is not the bare
    repo link, an issue/PR/release link, or a blob/tree@main path is flagged
    (permalinks to SHAs/tags/blame would dodge path checking).
    """
    problems = []
    source_links = 0
    for md in _docs_md():
        rel = md.relative_to(REPO_ROOT)
        for m in REPO_URL.finditer(md.read_text(encoding="utf-8")):
            tail = (m.group(1) or "").rstrip(".,;")
            if tail in ("", "/") or OTHER_OK_LINK.match(tail):
                continue
            sm = SOURCE_LINK.match(tail)
            if not sm:
                problems.append(f"{rel}: unsanctioned GitHub link shape {tail}")
                continue
            source_links += 1
            if not (REPO_ROOT / sm.group(1)).exists():
                problems.append(f"{rel}: dead path {sm.group(1)}")
            if sm.group(2) and re.match(r"#L\d", sm.group(2)):
                problems.append(f"{rel}: line-anchored link {tail}")
    assert source_links > 0, "no GitHub source links found -- extraction regex or docs are broken"
    assert not problems, "bad GitHub links:\n" + "\n".join(problems)


def _documented_rows() -> dict[str, str]:
    """configuration.md table rows: env var (first column code-span) -> Default cell.

    Column contract: `| Variable | Default | Description |`, validated
    per-table -- a reordered layout in any one grouped table fails loudly
    instead of comparing defaults against description prose.
    """
    text = (DOCS_DIR / "deployment" / "configuration.md").read_text(encoding="utf-8")
    header = re.compile(r"^\|\s*Variable\s*\|\s*Default\s*\|\s*Description\s*\|")
    row = re.compile(r"^\|\s*`([A-Z][A-Z0-9_]*)`\s*\|([^|]*)\|", flags=re.M)
    names: list[str] = []
    rows: dict[str, str] = {}
    for block in re.findall(r"(?:^\|.*(?:\n|$))+", text, flags=re.M):
        matches = row.findall(block)
        if not matches:
            continue
        first_line = block.splitlines()[0]
        assert header.match(first_line), (f"table with env-var rows lacks the canonical header: {first_line!r}")
        for name, cell in matches:
            names.append(name)
            rows[name] = cell
    dupes = {n for n in names if names.count(n) > 1}
    assert not dupes, f"env vars documented in more than one table row: {sorted(dupes)}"
    assert rows, "no documented env vars found in configuration.md -- table format changed?"
    return rows


def test_settings_documented_bidirectional():
    """Settings fields <-> configuration.md rows, both directions, token-exact."""
    from postern.settings import Settings

    fields = {name.upper() for name in Settings.model_fields}
    documented = set(_documented_rows())
    missing = fields - documented
    stale = documented - fields - _external_env_vars() - DOC_ONLY_VARS
    assert not missing, f"Settings fields undocumented in configuration.md: {sorted(missing)}"
    assert not stale, f"documented vars that exist neither in Settings nor in compose/example.env: {sorted(stale)}"


def test_settings_defaults_match():
    """The Default cell (first code-span) equals the settings.py default."""
    from pydantic_core import PydanticUndefined

    from postern.settings import Settings

    # default_factory fields are invisible to this gate; red loudly the
    # moment one appears so it gets an explicit disposition.
    factory_fields = [name for name, field in Settings.model_fields.items() if field.default_factory is not None]
    assert not factory_fields, f"extend this gate for default_factory fields: {factory_fields}"

    rows = _documented_rows()
    comparable = {
        name.upper(): field.default
        for name, field in Settings.model_fields.items() if field.default is not PydanticUndefined
    }
    problems = []
    checked = skipped = 0
    for name, default in comparable.items():
        cell = rows.get(name)
        if cell is None:
            skipped += 1  # absence is test_settings_documented_bidirectional's job
            continue
        if isinstance(default, bool):
            rendered = "true" if default else "false"
        elif default == "":
            rendered = '""'  # empty defaults are documented as `""`
        else:
            rendered = str(default)
        checked += 1
        # Exact compare on the cell's first code-span; substring matching
        # would false-pass 60-in-600 style drift.
        span = re.search(r"`([^`]*)`", cell)
        if span is None or span.group(1) != rendered:
            problems.append(f"{name}: docs say {cell.strip()!r}, settings.py says {rendered!r}")
    assert checked > 0, "no defaults were compared -- table format changed?"
    assert checked + skipped == len(comparable), "accounting drift in this gate's own logic"
    assert not problems, "documented defaults drifted from settings.py:\n" + "\n".join(problems)


def test_example_env_documented():
    """Every var assigned (or offered commented-out) in example.env is documented somewhere in docs/."""
    env_text = (REPO_ROOT / "example.env").read_text(encoding="utf-8")
    env_vars = set(re.findall(r"^\s*#?\s*([A-Z][A-Z0-9_]+)=", env_text, flags=re.M))
    assert env_vars, "no assignments found in example.env -- format changed?"
    docs_text = "".join(md.read_text(encoding="utf-8") for md in _docs_md())
    missing = [v for v in sorted(env_vars) if f"`{v}`" not in docs_text]
    assert not missing, f"example.env vars documented nowhere in docs/: {missing}"


def test_must_keep_caveats():
    """Deletion tripwire: each caveat's anchor phrase is still on its page.

    Presence-only by design; caveat MEANING is verified by review, not by
    this test.
    """
    problems = []
    for rel, tokens in MUST_KEEP.items():
        text = (DOCS_DIR / rel).read_text(encoding="utf-8")
        problems += [f"{rel}: missing {token!r}" for token in tokens if token not in text]
    assert not problems, "load-bearing caveat phrases dropped:\n" + "\n".join(problems)


def test_must_keep_code_mirrors():
    """Code-mirroring tripwires: the literal is on the page AND in its source of truth."""
    problems = []
    for rel, token, source in MUST_KEEP_CODE:
        if token not in (DOCS_DIR / rel).read_text(encoding="utf-8"):
            problems.append(f"{rel}: missing {token!r}")
        if token not in (REPO_ROOT / source).read_text(encoding="utf-8"):
            problems.append(f"{source}: no longer contains {token!r} -- update docs AND this gate")
    assert not problems, "code-mirroring tripwires broken:\n" + "\n".join(problems)


def test_compose_topology_references():
    """Compose file and profile names mentioned in docs exist in the repo."""
    compose_files = {p.name for p in REPO_ROOT.glob("compose*.yaml")}
    compose_text = "".join((REPO_ROOT / name).read_text(encoding="utf-8") for name in sorted(compose_files))
    problems = []
    checked = 0
    for md in _docs_md():
        rel = md.relative_to(REPO_ROOT)
        text = md.read_text(encoding="utf-8")
        for name in re.findall(r"\bcompose[\w.-]*\.ya?ml\b", text):
            checked += 1
            if name not in compose_files:
                problems.append(f"{rel}: unknown compose file {name}")
        for profile in re.findall(r"\bwith-[a-z][a-z-]*\b", text):
            checked += 1
            if profile not in compose_text:
                problems.append(f"{rel}: unknown compose profile {profile}")
    assert checked > 0, "no compose references found -- extraction regex or docs are broken"
    assert not problems, "stale compose topology references:\n" + "\n".join(problems)


def _typer_command_paths() -> set[str]:
    """All full command paths of the postern CLI, e.g. {'user add', 'reconcile', ...}."""
    import click
    from typer.main import get_command

    import postern.cli

    root = get_command(postern.cli.app)
    paths: set[str] = set()

    def walk(cmd, prefix: str) -> None:
        if isinstance(cmd, click.Group):
            for name, sub in cmd.commands.items():
                walk(sub, f"{prefix}{name} ")
        else:
            paths.add(prefix.strip())

    walk(root, "")
    return paths


def test_cli_reference_complete():
    """cli.md documents every CLI command as a `### postern <path>` heading -- exactly once each."""
    text = (DOCS_DIR / "operations" / "cli.md").read_text(encoding="utf-8")
    headings = re.findall(r"^### postern (.+?)\s*$", text, flags=re.M)
    dupes = {h for h in headings if headings.count(h) > 1}
    assert not dupes, f"commands documented more than once: {sorted(dupes)}"
    documented = set(headings)
    actual = _typer_command_paths()
    assert documented == actual, (f"undocumented: {sorted(actual - documented)}; stale: {sorted(documented - actual)}")


REAL_DOMAIN = re.compile(r"binarydreams\.me")


def test_no_real_domains():
    """docs/ never mentions the maintainer's real deployment domains."""
    # Sentinel self-check: a broken pattern must fail here, not pass vacuously.
    assert REAL_DOMAIN.search("hole." + "binarydreams" + ".me")
    hits = [f"{md.relative_to(REPO_ROOT)}" for md in _docs_md() if REAL_DOMAIN.search(md.read_text(encoding="utf-8"))]
    assert not hits, f"real domains leaked into docs: {hits}"
