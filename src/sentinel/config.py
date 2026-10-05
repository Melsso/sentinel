import ipaddress

from pydantic import field_validator
from pydantic_settings import BaseSettings

_MIN_JWT_SECRET_LENGTH = 32
_KNOWN_PLACEHOLDER_SECRETS = {
    "dev-secret-change-me",
    "change-me-to-a-real-secret",
    "change-me",
    "changeme",
    "secret",
    "ci-placeholder-secret",
    "test-secret",
}
_ALLOWED_JWT_ALGORITHMS = {"HS256", "HS384", "HS512"}


class Settings(BaseSettings):
    database_url: str
    redis_url: str

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "sentinel"
    jwt_audience: str = "sentinel-api"

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 30
    session_absolute_lifetime_days: int = 90
    session_retention_days: int = 7
    session_purge_interval_seconds: int = 3600

    log_pii: bool = False

    allow_console_email: bool = False
    email_send_attempts: int = 3
    email_retry_base_delay_seconds: float = 1.0

    email_verification_expire_minutes: int = 30
    password_reset_expire_minutes: int = 30

    login_rate_limit: int = 5
    login_rate_limit_window_seconds: int = 60

    register_rate_limit: int = 10
    register_rate_limit_window_seconds: int = 60

    forgot_password_rate_limit: int = 5
    forgot_password_rate_limit_window_seconds: int = 60

    resend_verification_rate_limit: int = 5
    resend_verification_rate_limit_window_seconds: int = 60

    login_lockout_threshold: int = 10
    login_lockout_duration_seconds: int = 900

    trusted_proxies: str = ""

    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    log_level: str = "INFO"

    email_backend: str = "console"
    email_from: str = "no-reply@sentinel.local"

    frontend_url: str = "http://localhost:3000"

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True

    @field_validator("jwt_secret")
    @classmethod
    def _check_jwt_secret(cls, value: str) -> str:
        if value.strip().lower() in _KNOWN_PLACEHOLDER_SECRETS:
            raise ValueError("JWT_SECRET is a known placeholder; generate a real one.")
        if len(value) < _MIN_JWT_SECRET_LENGTH:
            raise ValueError(
                f"JWT_SECRET must be at least {_MIN_JWT_SECRET_LENGTH} characters. "
                "Generate one with: python -c "
                '"import secrets; print(secrets.token_urlsafe(48))"'
            )
        return value

    @field_validator("jwt_algorithm")
    @classmethod
    def _check_jwt_algorithm(cls, value: str) -> str:
        if value not in _ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"JWT_ALGORITHM must be one of {sorted(_ALLOWED_JWT_ALGORITHMS)}."
            )
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _check_trusted_proxies(cls, value: str) -> str:
        for item in value.split(","):
            item = item.strip()
            if item:
                ipaddress.ip_network(item, strict=False)
        return value

    @property
    def cors_origins_list(self) -> list[str]:
        return [
            origin.strip() for origin in self.cors_origins.split(",") if origin.strip()
        ]

    class Config:
        env_file = ".env"


settings = Settings()
