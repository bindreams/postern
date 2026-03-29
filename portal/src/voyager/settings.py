from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables."""

    # Database =====
    database_path: str = "/data/voyager.db"

    # SMTP =====
    smtp_host: str = "localhost"
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@example.com"

    # Auth =====
    secret_key: str  # Required, no default -- app fails to start without it
    otp_expiry_seconds: int = 600  # 10 minutes
    otp_max_attempts: int = 5
    otp_max_requests_per_window: int = 3
    otp_rate_window_seconds: int = 900  # 15 minutes
    session_expiry_days: int = 7

    # Reconciler =====
    reconcile_interval_seconds: int = 60
    shadowsocks_image: str = "local/shadowsocks-server"
    shadowsocks_network: str = "shadowsocks"

    # Domain =====
    domain: str = "voyager.binarydreams.me"
