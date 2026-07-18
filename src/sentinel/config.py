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

    class Config:
        env_file = ".env"


settings = Settings()
