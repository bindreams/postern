"""End-to-end tests for the built-in MTA stack.

These tests boot the full ``postern-e2e-mta`` compose project (e2e.compose.yaml +
e2e-mta.compose.yaml) and exercise the production mta + provisioner images
against a mailpit "recipient MTA". No real DNS, no real outbound port 25.

Marker (`e2e_mta`) is added by ``conftest.pytest_collection_modifyitems``;
tests in this file do not declare ``pytestmark``.
"""

from __future__ import annotations

import json
import re
import time

import dkim  # dkimpy; in the e2e dependency group  # ty: ignore[unresolved-import]
import pytest

from ._mta_helpers import (
    PROJECT_MTA,
    docker_inspect,
    get_container_id,
    get_provisioner_state,
    mta_exec,
    network_inspect,
    portal_mta_exec,
    read_dkim_volume_file,
)

SELECTOR_RE = re.compile(r"^postern-\d{4}-\d{2}$")


# Fixtures =============================================================================================================
@pytest.fixture(scope="session")
def active_selector(mta_e2e_stack) -> str:
    """The single active DKIM selector for this session.

    Resolves the selector from state.json once, used by every test that needs it.
    """
    state = get_provisioner_state()
    selectors = state.get("active_selectors", [])
    assert len(selectors) == 1, f"expected exactly 1 active selector, got {selectors!r}"
    selector = selectors[0]
    assert SELECTOR_RE.match(selector), f"selector {selector!r} does not match postern-YYYY-MM"
    return selector


# Login flow helper ----------------------------------------------------------------------------------------------------
def _request_otp(portal_client, email: str) -> None:
    """POST /login to trigger an OTP email. Asserts the 303 redirect."""
    r = portal_client.post("/login", data={"email": email})
    assert r.status_code == 303, f"expected 303 from /login, got {r.status_code}: {r.text}"
    assert r.headers.get("location") == "/login/verify"


# Tests ================================================================================================================
def test_otp_email_is_dkim_signed(
    portal_mta_client,
    mailpit_mta_client,
    fresh_mta_user,
    active_selector,
):
    """Login flow → mailpit receives the OTP message; the DKIM-Signature header is
    present, signs `d=postern.test`, and uses the active selector."""
    email = "dkim-signed@postern.test"
    fresh_mta_user("DKIM Signed Test", email)
    _request_otp(portal_mta_client, email)

    msg = mailpit_mta_client.latest_to(email, timeout=30)
    headers = msg.get("Headers") or {}
    sig_values = headers.get("DKIM-Signature") or headers.get("Dkim-Signature") or []
    assert sig_values, f"no DKIM-Signature header on mailpit message; headers were {sorted(headers)!r}"
    sig = sig_values[0]
    assert "v=1" in sig, f"DKIM-Signature missing v=1: {sig!r}"

    fields = {k.strip(): v.strip() for kv in sig.split(";") if "=" in kv for k, v in [kv.split("=", 1)]}
    assert fields.get("d") == "postern.test", f"expected d=postern.test, got d={fields.get('d')!r}"
    assert fields.get("s") == active_selector, (f"expected s={active_selector!r}, got s={fields.get('s')!r}")


def test_dkim_signature_verifies(
    portal_mta_client,
    mailpit_mta_client,
    fresh_mta_user,
    active_selector,
):
    """End-to-end DKIM verification: mailpit's raw RFC 5322 source is verified by
    dkimpy using the public key read from the shared opendkim volume.

    Pins the cryptographic correctness of the signing pipeline (opendkim +
    keypair on the volume) -- not just the presence of the header.
    """
    email = "dkim-verify@postern.test"
    fresh_mta_user("DKIM Verify Test", email)
    _request_otp(portal_mta_client, email)

    msg = mailpit_mta_client.latest_to(email, timeout=30)
    raw = mailpit_mta_client.get_raw_source(msg["ID"])
    assert raw, "mailpit returned empty raw source"

    # Read the opendkim public-key TXT file via the portal's :ro mount of the
    # shared volume. The file is in the canonical opendkim-genkey format:
    #   <selector>._domainkey IN TXT ("v=DKIM1; k=rsa; "
    #             "p=BASE64BASE64..."
    #             ) ; ----- DKIM key <selector> for ...
    pubkey_file = read_dkim_volume_file(f"{active_selector}.txt")
    m = re.search(r'p=([A-Za-z0-9+/=\s"]+)', pubkey_file)
    assert m, f"could not find p= in pubkey file:\n{pubkey_file!r}"
    pubkey = re.sub(r'[\s")]', "", m.group(1))

    expected_name = f"{active_selector}._domainkey.postern.test.".encode()
    record = f"v=DKIM1; k=rsa; p={pubkey}".encode()

    def dnsfunc(name: bytes, timeout: int = 5) -> bytes:
        # dkimpy passes the FQDN as bytes; we verify its shape and return the bytes record.
        assert name == expected_name, f"unexpected DKIM lookup: {name!r} (expected {expected_name!r})"
        return record

    assert dkim.verify(raw, dnsfunc=dnsfunc), "dkim.verify returned False against locally-rendered pubkey"


def test_provisioner_generates_initial_state_json(mta_e2e_stack):
    """The provisioner writes state.json with state=STABLE and a single
    date-suffixed selector before the mta is allowed to start (mta's
    ``depends_on: provisioner: service_completed_successfully`` enforces order)."""
    state = get_provisioner_state()
    assert state.get("state") == "STABLE", f"expected state=STABLE, got {state.get('state')!r}"
    selectors = state.get("active_selectors", [])
    assert len(selectors) == 1, f"expected 1 active selector, got {selectors!r}"
    assert SELECTOR_RE.match(selectors[0]), f"selector {selectors[0]!r} not in postern-YYYY-MM form"
    assert state.get("retiring_selector"
                     ) in (None,
                           ""), (f"unexpected retiring_selector at session start: {state.get('retiring_selector')!r}")


def test_provisioner_exits_cleanly_when_dns_provider_none(mta_e2e_stack):
    """With MTA_DNS_PROVIDER=none, the provisioner exits 0 after the initial
    keypair is generated. The container is ``restart: 'no'`` so it stays
    exited; mta's ``depends_on`` condition relies on this exit semantics."""
    cid = get_container_id("provisioner")
    status = docker_inspect(cid, "{{.State.Status}}")
    assert status == "exited", f"expected provisioner status=exited, got {status!r}"
    exit_code = docker_inspect(cid, "{{.State.ExitCode}}")
    assert exit_code == "0", f"expected provisioner exit 0, got {exit_code!r}"


def test_postmaster_forwards_to_admin_email(mta_e2e_stack, mailpit_mta_client):
    """sendmail postmaster@postern.test (from inside mta) -> mailpit shows the
    message addressed to admin@elsewhere.test, exercising:
      - virtual_alias_maps (postmaster -> admin)
      - transport_maps (elsewhere.test -> [172.30.99.10]:1025)
      - SRS envelope-sender rewriting (postsrsd via sender_canonical_maps)
    """
    payload = (
        "From: probe@postern.test\r\n"
        "To: postmaster@postern.test\r\n"
        "Subject: e2e postmaster forwarding probe\r\n"
        "\r\n"
        "body\r\n"
    )
    # postfix's sendmail wrapper reads the message from stdin; -i ignores
    # leading-dot lines (we don't have any but this matches sendmail conventions).
    mta_exec("sendmail", "-i", "postmaster@postern.test", stdin=payload)

    # Wait for postfix to push the message via smtp:[mailpit-ip]:1025 -> mailpit.
    msg = mailpit_mta_client.latest_to("admin@elsewhere.test", timeout=30)
    assert msg["ID"], "mailpit message has no ID"


def test_mta_listens_on_smtp_and_submission_ports(mta_e2e_stack):
    """mta's compose healthcheck probes both 25 and 587; if either listener is
    down, the container is unhealthy. Pinning the health status here surfaces
    a regression of either listener as a clean failure mode."""
    cid = get_container_id("mta")
    status = docker_inspect(cid, "{{.State.Health.Status}}")
    assert status == "healthy", f"mta container is {status!r}, expected 'healthy'"


def test_mta_submit_network_is_internal(mta_e2e_stack):
    """`mta-submit` is internal: true with the fixed /29 subnet (architectural
    invariant in CLAUDE.md). A "simplification" that drops `internal: true`
    would let any service relay through mta unauthenticated."""
    info = network_inspect("mta-submit-mta-e2e")
    assert info.get("Internal") is True, f"network not internal: Internal={info.get('Internal')!r}"
    cfgs = (info.get("IPAM", {}) or {}).get("Config", []) or []
    subnets = [c.get("Subnet") for c in cfgs]
    assert "172.30.42.0/29" in subnets, f"expected /29 subnet 172.30.42.0/29, got {subnets!r}"


def test_opendkim_runs_as_uid_gid_110(mta_e2e_stack, active_selector):
    """opendkim's UID/GID is pinned at 110:110 in BOTH mta and provisioner
    Dockerfiles. The shared `postern-mta-data` volume permissions depend on
    them matching (CLAUDE.md invariant). stat the .private key file (which
    the provisioner writes and opendkim reads)."""
    out = mta_exec("stat", "-c", "%u:%g", f"/var/lib/opendkim/{active_selector}.private").stdout.strip()
    assert out == "110:110", f"expected 110:110, got {out!r}"


def test_opendkim_table_signs_with_latest_selector(mta_e2e_stack, active_selector):
    """The opendkim KeyTable + SigningTable are emitted from rotation state by
    the entrypoint. SigningTable maps `*@postern.test` to the active selector;
    KeyTable maps the selector record to the .private file path."""
    keytable = mta_exec("cat", "/etc/opendkim/KeyTable").stdout
    signingtable = mta_exec("cat", "/etc/opendkim/SigningTable").stdout

    # SigningTable: `*@postern.test postern-YYYY-MM._domainkey.postern.test`
    expected_signing = f"*@postern.test {active_selector}._domainkey.postern.test"
    assert expected_signing in signingtable, (
        f"SigningTable does not contain {expected_signing!r}; got:\n{signingtable!r}"
    )

    # KeyTable: `<selector>._domainkey.postern.test postern.test:<selector>:/var/lib/opendkim/<selector>.private`
    expected_key = (
        f"{active_selector}._domainkey.postern.test "
        f"postern.test:{active_selector}:/var/lib/opendkim/{active_selector}.private"
    )
    assert expected_key in keytable, (f"KeyTable does not contain {expected_key!r}; got:\n{keytable!r}")
