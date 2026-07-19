import pytest

from sentinel.config import settings
from tests.conftest import unique_email


pytestmark = pytest.mark.asyncio


def _clear_rate_limit_keys(redis):
    for key in [k for k in redis.storage if k.startswith("ratelimit:")]:
        del redis.storage[key]


def _clear_lockout_keys(redis):
    for key in [
        k
        for k in redis.storage
        if k.startswith("login_lockout:") or k.startswith("login_failures:")
    ]:
        del redis.storage[key]


async def test_login_blocked_after_too_many_attempts(client, verified_user, redis):
    user = await verified_user()
    limit = settings.login_rate_limit

    for _ in range(limit):
        response = await client.post(
            "/auth/login",
            json={"email": user["email"], "password": "wrong-password"},
        )
        assert response.status_code == 401

    blocked = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": "wrong-password"},
    )

    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


async def test_login_successful_attempts_also_count(client, verified_user):
    user = await verified_user()
    limit = settings.login_rate_limit

    for _ in range(limit):
        response = await client.post(
            "/auth/login",
            json={"email": user["email"], "password": user["password"]},
        )
        assert response.status_code == 200

    blocked = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )

    assert blocked.status_code == 429


async def test_login_rate_limit_is_per_email(client, verified_user):
    limit = settings.login_rate_limit
    victim = await verified_user()
    bystander = await verified_user()

    for _ in range(limit):
        response = await client.post(
            "/auth/login",
            json={"email": victim["email"], "password": "wrong-password"},
            headers={"X-Forwarded-For": "10.0.0.1"},
        )
        assert response.status_code == 401

    blocked = await client.post(
        "/auth/login",
        json={"email": victim["email"], "password": "wrong-password"},
        headers={"X-Forwarded-For": "10.0.0.1"},
    )
    assert blocked.status_code == 429

    bystander_response = await client.post(
        "/auth/login",
        json={"email": bystander["email"], "password": bystander["password"]},
        headers={"X-Forwarded-For": "10.0.0.2"},
    )
    assert bystander_response.status_code == 200


async def test_login_rate_limit_is_per_ip(client, verified_user):
    """A single IP cycling through many different accounts should still get
    capped, even though no individual account's limit is exceeded."""
    limit = settings.login_rate_limit
    users = [await verified_user() for _ in range(limit + 1)]

    for user in users[:limit]:
        response = await client.post(
            "/auth/login",
            json={"email": user["email"], "password": user["password"]},
            headers={"X-Forwarded-For": "10.0.0.9"},
        )
        assert response.status_code == 200

    blocked = await client.post(
        "/auth/login",
        json={"email": users[-1]["email"], "password": users[-1]["password"]},
        headers={"X-Forwarded-For": "10.0.0.9"},
    )
    assert blocked.status_code == 429


async def test_login_rate_limit_resets_after_window(client, verified_user, redis):
    user = await verified_user()
    limit = settings.login_rate_limit

    for _ in range(limit):
        await client.post(
            "/auth/login",
            json={"email": user["email"], "password": "wrong-password"},
        )

    blocked = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": "wrong-password"},
    )
    assert blocked.status_code == 429

    _clear_rate_limit_keys(redis)
    _clear_lockout_keys(redis)

    recovered = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert recovered.status_code == 200


async def test_register_blocked_after_too_many_attempts(client):
    limit = settings.register_rate_limit

    for _ in range(limit):
        response = await client.post(
            "/auth/register",
            json={"email": unique_email(), "password": "Password123!"},
        )
        assert response.status_code == 201

    blocked = await client.post(
        "/auth/register",
        json={"email": unique_email(), "password": "Password123!"},
    )

    assert blocked.status_code == 429


async def test_forgot_password_blocked_after_too_many_attempts(client, verified_user):
    user = await verified_user()
    limit = settings.forgot_password_rate_limit

    for _ in range(limit):
        response = await client.post(
            "/auth/forgot-password", json={"email": user["email"]}
        )
        assert response.status_code == 200

    blocked = await client.post("/auth/forgot-password", json={"email": user["email"]})

    assert blocked.status_code == 429


async def test_resend_verification_blocked_after_too_many_attempts(client, register):
    email, _, _ = await register()
    limit = settings.resend_verification_rate_limit

    for _ in range(limit):
        response = await client.post(
            "/auth/resend-verification-email", json={"email": email}
        )
        assert response.status_code == 200

    blocked = await client.post(
        "/auth/resend-verification-email", json={"email": email}
    )

    assert blocked.status_code == 429
