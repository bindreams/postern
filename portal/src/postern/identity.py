"""Visitor identity enrichment for the login page.

Combines the source IP (from nginx's ``X-Real-IP`` header, defensively validated)
with optional MaxMind GeoLite2 City + ASN MMDB lookups, plus a parsed User-Agent
summary, into a single :class:`IdentityInfo` dataclass.

GeoIP databases are owned by the operator and bind-mounted read-only into the
portal container; see ``docs/frontend.md``. If no DBs are configured, lookup
still returns a populated IP + UA summary and leaves the geo/asn fields ``None``.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import maxminddb
from user_agents import parse as _parse_user_agent

if TYPE_CHECKING:
    from fastapi import Request

logger = logging.getLogger(__name__)

_CITY_FILENAME = "GeoLite2-City.mmdb"
_ASN_FILENAME = "GeoLite2-ASN.mmdb"


# Public dataclass =====================================================================================================
@dataclass(frozen=True, slots=True)
class IdentityInfo:
    """A snapshot of "who is hitting this page" for the login screen.

    All fields except `ip` and `client` may be ``None`` -- enrichment is best-effort
    and absent for private / loopback addresses or when MMDB files are not mounted.
    """

    ip: str
    country_code: str | None  # ISO 3166-1 alpha-2, LOWERCASED (matches flag filename).
    city: str | None
    isp: str | None  # AutonomousSystemOrganization, e.g. "Magenta Telekom"
    asn: str | None  # "AS8412"
    client: str  # short summary, e.g. "Chrome 142 · macOS"; never None.


# GeoIP reader holder ==================================================================================================
class GeoIPReaders:
    """Lazy holder for the City + ASN MMDB readers.

    Constructed once at portal lifespan startup with the configured ``geoip_db_dir``;
    re-opens individual readers when the underlying file's mtime changes (so operators
    can hot-swap monthly MaxMind updates without a portal restart). Closed at shutdown.

    Thread-safe: ``maxminddb.Reader.get()`` itself is thread-safe; the open/reopen
    paths are serialized with an internal ``threading.Lock``.
    """

    def __init__(self, db_dir: str):
        self.db_dir = Path(db_dir) if db_dir else None
        self._lock = threading.Lock()
        self._city: maxminddb.Reader | None = None
        self._asn: maxminddb.Reader | None = None
        self._mtimes: dict[str, float] = {}

    def close(self) -> None:
        with self._lock:
            for reader in (self._city, self._asn):
                if reader is not None:
                    try:
                        reader.close()
                    except Exception:  # noqa: BLE001 -- shutdown path, best-effort
                        logger.debug("GeoIPReaders.close: ignored close() error", exc_info=True)
            self._city = None
            self._asn = None
            self._mtimes.clear()

    def _stat_or_reopen(self, filename: str, current: maxminddb.Reader | None) -> maxminddb.Reader | None:
        """Return an open Reader for ``<db_dir>/<filename>``, or ``None`` if absent.

        Re-opens the file when its mtime has changed since the last call.
        """
        if self.db_dir is None:
            return None
        path = self.db_dir / filename
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            if current is not None:
                try:
                    current.close()
                except Exception:
                    logger.debug("close after FileNotFoundError failed", exc_info=True)
            self._mtimes.pop(filename, None)
            return None
        except OSError:
            logger.warning("GeoIP DB %s stat failed; falling back to IP-only", path, exc_info=True)
            return current
        prior = self._mtimes.get(filename)
        # Cache hit covers two cases under the same mtime: (a) we have a live
        # reader open against this exact mtime -- return it; (b) we know this
        # mtime represents a broken file we already failed to open -- skip the
        # retry. Case (b) is the broken-file pin: without it, every request
        # would re-attempt open_database on a known-bad file.
        if prior == mtime:
            return current
        try:
            reader = maxminddb.open_database(str(path))
        except (maxminddb.InvalidDatabaseError, OSError):
            # Pin the failed mtime so subsequent requests don't retry the broken
            # file on every hit -- that would log-spam and burn CPU. We only
            # re-attempt once the operator writes a new mtime to the file, which
            # is exactly the "I fixed it" signal we want to watch for. Logging
            # happens at most once per mtime change.
            logger.warning("GeoIP DB %s failed to open; pinning mtime, will retry on next change", path, exc_info=True)
            self._mtimes[filename] = mtime
            return current
        if current is not None:
            try:
                current.close()
            except Exception:
                logger.debug("close on hot-swap failed", exc_info=True)
        self._mtimes[filename] = mtime
        return reader

    def city(self) -> maxminddb.Reader | None:
        with self._lock:
            self._city = self._stat_or_reopen(_CITY_FILENAME, self._city)
            return self._city

    def asn(self) -> maxminddb.Reader | None:
        with self._lock:
            self._asn = self._stat_or_reopen(_ASN_FILENAME, self._asn)
            return self._asn


# IP extraction ========================================================================================================
# RFC1918 + IPv6 unique-local + loopback + link-local. We explicitly enumerate
# instead of using ``ipaddress.is_private`` because that flag also covers
# documentation/reserved ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
# which are perfectly valid as PUBLIC source addresses and must not be allowed
# to satisfy "the in-cluster proxy hop" test.
_TRUSTED_PROXY_NETS = tuple(
    ipaddress.ip_network(cidr) for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _is_trusted_proxy_hop(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _TRUSTED_PROXY_NETS)


def _client_ip(request: Request) -> str:
    """Extract the visitor's IP from the request, trusting X-Real-IP only when warranted.

    Nginx is the only documented ingress for Postern and sets X-Real-IP on every
    proxied request, but this guard makes the behavior safe even if someone ever
    runs the portal behind a different proxy or exposes it directly: X-Real-IP is
    trusted only when the direct socket peer is in a real private/loopback range
    (RFC1918, ULA, ::1, link-local). Anything else uses the socket peer directly.
    """
    direct = request.client.host if request.client else ""
    xri = request.headers.get("X-Real-IP", "").strip()
    if not xri:
        return direct
    # `request.client` can be None for non-TCP ASGI scopes (lifespan-internal,
    # synthetic test clients, etc.). In that case we have no direct socket peer
    # to make the trust decision against; trust X-Real-IP, since (a) the only
    # way the request reached the app at all is via in-process plumbing or a
    # locally-configured proxy that already terminated the connection, and (b)
    # returning "" instead would force the identity card to render "unknown"
    # despite the upstream having told us exactly who the visitor is.
    if not direct:
        return xri
    try:
        addr = ipaddress.ip_address(direct)
    except ValueError:
        return direct
    if _is_trusted_proxy_hop(addr):
        return xri
    return direct


def _should_skip_enrichment(ip: str) -> bool:
    """Skip MMDB enrichment for IPs that can never produce a meaningful record.

    Concretely: empty string, RFC1918, ULA, loopback, link-local, multicast, or
    the unspecified address. Documentation/test-net ranges (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24) are NOT skipped: they look "global" enough
    to MaxMind that a deliberately-crafted MMDB can return entries for them, and
    that property is what the test suite leans on.
    """
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if _is_trusted_proxy_hop(addr):
        return True
    return addr.is_multicast or addr.is_unspecified


# UA summary ===========================================================================================================
def _summarize_user_agent(ua_string: str) -> str:
    """Return a compact "Browser version · OS" string. Falls back to "Unknown client"."""
    if not ua_string:
        return "Unknown client"
    try:
        ua = _parse_user_agent(ua_string)
    except Exception:  # noqa: BLE001
        return "Unknown client"
    browser = (ua.browser.family or "").strip()
    os_family = (ua.os.family or "").strip()
    if not browser or browser.lower() in {"other", ""}:
        return "Unknown client"
    # version_string can be "" for some UAs; emit just the family in that case.
    version = (ua.browser.version_string or "").split(".")[0]
    parts: list[str] = []
    if version:
        parts.append(f"{browser} {version}")
    else:
        parts.append(browser)
    if os_family and os_family.lower() != "other":
        parts.append(os_family)
    return " · ".join(parts) if len(parts) > 1 else f"{parts[0]} · Unknown OS"


# Geo / ASN lookup =====================================================================================================
def _safe_get(reader: maxminddb.Reader | None, ip: str) -> dict[str, Any] | None:
    if reader is None:
        return None
    try:
        record = reader.get(ip)
    except (ValueError, maxminddb.InvalidDatabaseError):
        logger.debug("MMDB lookup raised for %s", ip, exc_info=True)
        return None
    if isinstance(record, dict):
        return record
    return None


def _extract_country_and_city(record: dict[str, Any] | None) -> tuple[str | None, str | None]:
    if not record:
        return None, None
    country = record.get("country") or {}
    iso = country.get("iso_code") if isinstance(country, dict) else None
    city = record.get("city") or {}
    city_name: str | None = None
    if isinstance(city, dict):
        names = city.get("names")
        if isinstance(names, dict):
            city_name = names.get("en")
    return (iso.lower() if isinstance(iso, str) else None), city_name


def _extract_asn(record: dict[str, Any] | None) -> tuple[str | None, str | None]:
    if not record:
        return None, None
    org = record.get("autonomous_system_organization")
    num = record.get("autonomous_system_number")
    asn = f"AS{num}" if isinstance(num, int) else None
    return (org if isinstance(org, str) else None), asn


# Public entry point ===================================================================================================
def lookup(request: Request, *, readers: GeoIPReaders | None) -> IdentityInfo:
    """Build an :class:`IdentityInfo` for the current request.

    Always returns a value; never raises for missing DBs, unparseable UAs, or
    spoofed headers. Loopback / RFC1918 / link-local IPs skip MMDB enrichment.
    """
    ip = _client_ip(request)
    ua = request.headers.get("User-Agent", "")
    client_summary = _summarize_user_agent(ua)

    if _should_skip_enrichment(ip) or readers is None:
        return IdentityInfo(ip=ip, country_code=None, city=None, isp=None, asn=None, client=client_summary)

    city_record = _safe_get(readers.city(), ip)
    asn_record = _safe_get(readers.asn(), ip)
    country_code, city = _extract_country_and_city(city_record)
    isp, asn = _extract_asn(asn_record)

    return IdentityInfo(
        ip=ip,
        country_code=country_code,
        city=city,
        isp=isp,
        asn=asn,
        client=client_summary,
    )
