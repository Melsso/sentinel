import pytest
from pydantic import ValidationError

from sentinel.config import Settings

_BASE = {
    "database_url": "sqlite+aiosqlite:///:memory:",
    "redis_url": "redis://localhost:6379",
}


def _build(**overrides) -> Settings:
    return Settings(_env_file=None, **{**_BASE, **overrides})


@pytest.mark.parametrize("secret", ["", "short", "dev-secret-change-me", "x" * 31])
def test_weak_jwt_secrets_are_refused(secret):
    with pytest.raises(ValidationError):
        _build(jwt_secret=secret)


def test_strong_jwt_secret_is_accepted():
    assert _build(jwt_secret="x" * 32).jwt_secret == "x" * 32


def test_unsupported_jwt_algorithm_is_refused():
    with pytest.raises(ValidationError):
        _build(jwt_secret="x" * 32, jwt_algorithm="none")


def test_invalid_trusted_proxy_is_refused():
    with pytest.raises(ValidationError):
        _build(jwt_secret="x" * 32, trusted_proxies="not-an-ip")


def test_valid_trusted_proxies_are_accepted():
    settings = _build(jwt_secret="x" * 32, trusted_proxies="10.0.0.0/8, 127.0.0.1")

    assert settings.trusted_proxies == "10.0.0.0/8, 127.0.0.1"
