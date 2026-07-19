from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    redis_url: str

    jwt_secret: str
    jwt_algorithm: str = "HS256"

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 30

    email_verification_expire_minutes: int = 30
    password_reset_expire_minutes: int = 30

    login_rate_limit: int = 5
    login_rate_limit_window_seconds: int = 60

    register_rate_limit: int = 10
    register_rate_limit_window_seconds: int = 60

    forgot_password_rate_limit: int = 5
    forgot_password_rate_limit_window_seconds: int = 60

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

    @property
    def cors_origins_list(self) -> list[str]:
        return [
            origin.strip() for origin in self.cors_origins.split(",") if origin.strip()
        ]

    class Config:
        env_file = ".env"


settings = Settings()
