from typing import Any, Literal, Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables."""

    # Database =========================================================================================================
    database_path: str = "/data/postern.db"

    # SMTP =============================================================================================================
    smtp_host: str = "localhost"
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@example.com"

    # Auth =============================================================================================================
    secret_key: str  # Required, no default -- app fails to start without it
    otp_expiry_seconds: int = 600  # 10 minutes
    otp_max_attempts: int = 5
    otp_max_requests_per_window: int = 3
    otp_rate_window_seconds: int = 900  # 15 minutes
    session_expiry_days: int = 7

    # Reconciler =======================================================================================================
    reconcile_interval_seconds: int = 60
    shadowsocks_image: str = "local/shadowsocks-server"
    shadowsocks_network: str = "shadowsocks"

    # Domain ===========================================================================================================
    domain: str = "postern.example.com"

    # Branding =========================================================================================================
    # Cosmetic display name shown in UI page titles, the OTP-email subject, and the
    # downloaded-config filename prefix. Decoupled from `domain` and from
    # `mta_dkim_selector_prefix` (the base for `<base>1`/`<base>2` rotating DKIM
    # selectors, defaulting to the common, non-identifying "s").
    product_name: str = "Postern"

    # Frontend =========================================================================================================
    # Absolute path to a custom brand icon (SVG preferred, PNG accepted; <= 256 KB).
    # Served via the /brand-icon route, which falls back to a built-in default SVG
    # on any error (missing file, oversized, disallowed extension, etc.). Empty
    # default means the built-in icon ships unchanged.
    product_icon_path: str = ""
    # Directory containing GeoLite2-City.mmdb + GeoLite2-ASN.mmdb. When set, the
    # login page renders an "appear-as" identity card with country/city/ISP/ASN.
    # When empty, the card still renders with the IP address only. See
    # docs/deployment/customization.md for the operator workflow.
    geoip_db_dir: str = ""

    # MTA ==============================================================================================================
    mta_verify_dns: bool = True
    mta_require_dnssec: bool | Literal["auto"] = "auto"
    mta_dkim_selector_prefix: str = "s"
    mta_admin_email: str = ""
    mta_dkim_rotation_days: int = 180

    # DNS provider (shared by DKIM rotation and cert renewal) ==========================================================
    dns_provider: str = "none"

    # Cert renewal =====================================================================================================
    cert_renewal: bool = False
    cert_acme_email: str = ""
    cert_acme_directory: str = "https://acme-v02.api.letsencrypt.org/directory"
    cert_renewal_days_before_expiry: int = 30
    cert_force_reissue: bool = False

    # Edge (CDN / reverse-proxy fronting the public :443 endpoint) =====================================================
    # "none" (default) is direct-to-origin. "cloudflare" orange-clouds the apex
    # through Cloudflare (real client IP recovered from CF's published ranges,
    # optional Authenticated Origin Pull mTLS). "generic" is any other trusted
    # reverse proxy that sets a real-IP header. See docs/deployment/edge.md.
    edge_profile: Literal["none", "cloudflare", "generic"] = "none"
    # generic profile only: the CIDR(s) allowed to set EDGE_REALIP_HEADER, and the
    # header name to trust. The CIDR list is comma/space/tab/newline-separated.
    edge_trusted_cidrs: str = ""
    edge_realip_header: str = ""
    # cloudflare profile only: require Cloudflare Authenticated Origin Pull (mTLS
    # against CF's global origin-pull CA). On by default; turning it off drops a
    # defence-in-depth layer. Meaningful ONLY under edge_profile=cloudflare --
    # setting it under any other profile fails loud.
    edge_cf_authenticated_origin_pull: bool = True
    # cloudflare profile only: opt in to postern auto-enabling Cloudflare's zone-level
    # ECH setting (publishes ech= in the apex HTTPS record). OFF by default: the toggle
    # is zone-WIDE and requires a Zone Settings:Edit CF token, and ECH can break clients
    # on hostile networks, so it is not auto-on. Meaningful ONLY under edge_profile=cloudflare.
    edge_cf_manage_zone_ech: bool = False
    # cloudflare profile only: auto-manage the zone's SSL/TLS encryption mode (raise-only,
    # see cloudflare_ssl.go). Default-ON (opt-out) UNLIKE zone-ECH: a Flexible/Off zone is a
    # hard ERR_TOO_MANY_REDIRECTS breakage. Zone-WIDE + needs a Zone Settings:Edit token.
    # Meaningful ONLY under edge_profile=cloudflare; explicit-set under another profile fails loud.
    edge_cf_manage_ssl_mode: bool = True
    # cloudflare profile only: target mode to raise to. "strict" validates the origin
    # cert; "full" suits a shared zone with an invalid-cert co-tenant. Typed `str`, not
    # `Literal` -- see the value-check in _check_edge_settings for why (scoped to when
    # management is active, matching the provisioner).
    edge_cf_ssl_mode: str = "strict"

    # ECH (client SNI concealment) =====================================================================================
    # ECH mode is per-connection (connections.ech: never/auto/always). This is only
    # the DoH resolver the plugin uses to fetch the front's ECH config for
    # auto/always connections (and that `postern ech verify` queries).
    ech_doh_url: str = "https://cloudflare-dns.com/dns-query"

    # Public IPs (cert manager publishes apex/wildcard A/AAAA when CERT_RENEWAL=true) ==================================
    # IPv4 required when CERT_RENEWAL=true. IPv6 optional; if set, AAAA records are
    # published; if previously published and now unset, AAAA records are deleted
    # (delete-on-unset, to avoid stale AAAA pointing at an old address after a
    # v6 -> v4-only migration).
    public_ipv4: str = ""
    public_ipv6: str = ""

    @field_validator("secret_key")
    @classmethod
    def _reject_placeholder(cls, v: str) -> str:
        if v == "REPLACE_WITH_HEX_STRING":
            raise ValueError(
                "SECRET_KEY is still the example.env placeholder; "
                "generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @field_validator("ech_doh_url")
    @classmethod
    def _validate_ech_doh_url(cls, v: str) -> str:
        # Applied whenever a value is present: the DoH URL is spliced verbatim into the
        # ;-separated SIP003 plugin_opts, so it must be a well-formed https URL with no
        # SIP003 metacharacters. Empty is allowed here ("not configured").
        if not v:
            return v
        from urllib.parse import unquote, urlsplit
        parts = urlsplit(v)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("ECH_DOH_URL must be an https:// URL with a host")
        # Scan the percent-DECODED form too, so an encoded metachar (e.g. %3B -> ';')
        # cannot smuggle a separator past this check.
        decoded = unquote(v)
        if any(c.isspace() for c in decoded) or ";" in decoded or "\\" in decoded:
            raise ValueError("ECH_DOH_URL must not contain whitespace, ';', or '\\' (SIP003 metacharacters)")
        return v

    @field_validator("mta_require_dnssec", mode="before")
    @classmethod
    def _normalize_require_dnssec(cls, v: Any) -> bool | Literal["auto"]:
        # Imported lazily to keep module-load cheap and avoid any chance of a cycle.
        from postern.mta.dnssec import parse_setting
        return parse_setting(v)

    @field_validator("mta_dkim_selector_prefix")
    @classmethod
    def _validate_dkim_selector_base(cls, v: str) -> str:
        from postern.mta.rotation import validate_selector_base
        return validate_selector_base(v)

    @model_validator(mode="after")
    def _check_cert_settings(self) -> Self:
        if self.cert_renewal:
            if self.dns_provider == "none":
                raise ValueError("CERT_RENEWAL=true requires DNS_PROVIDER to be set")
            if not self.cert_acme_email:
                raise ValueError("CERT_RENEWAL=true requires CERT_ACME_EMAIL")
            if "@example." in self.cert_acme_email:
                raise ValueError("CERT_ACME_EMAIL cannot be an example.com / example.org address")
            if not self.public_ipv4:
                raise ValueError(
                    "CERT_RENEWAL=true requires PUBLIC_IPV4 (the cert manager publishes A/AAAA "
                    "records for ${DOMAIN}, *.${DOMAIN}, and mail.${DOMAIN})"
                )
            # Validate IP formats. Lazy import to avoid extra deps at module load.
            from postern_provisioner.dns_records import validate_ipv4, validate_ipv6
            validate_ipv4(self.public_ipv4)
            if self.public_ipv6:
                validate_ipv6(self.public_ipv6)
        if self.cert_renewal_days_before_expiry < 1:
            raise ValueError("CERT_RENEWAL_DAYS_BEFORE_EXPIRY must be >= 1")
        return self

    @model_validator(mode="after")
    def _check_edge_settings(self) -> Self:
        # Strip before the emptiness test: a whitespace-only value is a
        # misconfiguration, not a valid setting, and must be rejected loudly.
        if self.edge_profile == "cloudflare":
            if self.dns_provider != "cloudflare":
                raise ValueError(
                    "EDGE_PROFILE=cloudflare requires DNS_PROVIDER=cloudflare "
                    "(the provisioner publishes proxied apex records via the Cloudflare API)"
                )
            if not self.public_ipv4.strip():
                raise ValueError(
                    "EDGE_PROFILE=cloudflare requires PUBLIC_IPV4 "
                    "(the origin address Cloudflare proxies the apex A record to)"
                )
        elif self.edge_profile == "generic":
            if not self.edge_trusted_cidrs.strip():
                raise ValueError(
                    "EDGE_PROFILE=generic requires EDGE_TRUSTED_CIDRS "
                    "(the CIDR(s) allowed to set the real-IP header)"
                )
            if not self.edge_realip_header.strip():
                raise ValueError(
                    "EDGE_PROFILE=generic requires EDGE_REALIP_HEADER "
                    "(the header name carrying the real client IP)"
                )
        # AOP is a Cloudflare-only knob. Explicitly configuring it under any other
        # profile is silently ignored today; fail loud instead of misleading the
        # operator into thinking mTLS is (dis)engaged.
        if (self.edge_profile != "cloudflare" and "edge_cf_authenticated_origin_pull" in self.model_fields_set):
            raise ValueError("EDGE_CF_AUTHENTICATED_ORIGIN_PULL is only meaningful under EDGE_PROFILE=cloudflare")
        if (self.edge_profile != "cloudflare" and "edge_cf_manage_zone_ech" in self.model_fields_set):
            raise ValueError("EDGE_CF_MANAGE_ZONE_ECH is only meaningful under EDGE_PROFILE=cloudflare")
        if (self.edge_profile != "cloudflare" and "edge_cf_manage_ssl_mode" in self.model_fields_set):
            raise ValueError("EDGE_CF_MANAGE_SSL_MODE is only meaningful under EDGE_PROFILE=cloudflare")
        if (self.edge_profile != "cloudflare" and "edge_cf_ssl_mode" in self.model_fields_set):
            raise ValueError("EDGE_CF_SSL_MODE is only meaningful under EDGE_PROFILE=cloudflare")
        # Enforce the full/strict VALUE only when management is actually active. This scopes
        # the check to exactly when the provisioner consumes it (ssl_mode_enabled = cloudflare
        # edge + cloudflare provider + manage), so the two containers -- which both read the
        # same EDGE_CF_SSL_MODE env with no shared validator -- accept/reject the identical
        # set. A stray value under manage=false is inert and must not split the stack (portal
        # crashing while the provisioner boots). Exact-match, mirroring ssl_mode.parse_ssl_target.
        if (
            self.edge_profile == "cloudflare" and self.edge_cf_manage_ssl_mode
            and self.edge_cf_ssl_mode not in ("full", "strict")
        ):
            raise ValueError(f"EDGE_CF_SSL_MODE must be 'full' or 'strict' (got {self.edge_cf_ssl_mode!r})")
        return self
