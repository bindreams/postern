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
    # `mta_dkim_selector_prefix` (which is part of the public DKIM record namespace
    # and stays "postern" by default).
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
    # docs/frontend.md for the operator workflow.
    geoip_db_dir: str = ""

    # MTA ==============================================================================================================
    mta_verify_dns: bool = True
    mta_require_dnssec: bool | Literal["auto"] = "auto"
    mta_dkim_selector_prefix: str = "postern"
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
                "SECRET_KEY is still the .env.example placeholder; "
                "generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @field_validator("mta_require_dnssec", mode="before")
    @classmethod
    def _normalize_require_dnssec(cls, v: Any) -> bool | Literal["auto"]:
        # Imported lazily to keep module-load cheap and avoid any chance of a cycle.
        from postern.mta.dnssec import parse_setting
        return parse_setting(v)

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
