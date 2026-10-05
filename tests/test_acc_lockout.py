import pytest

from sentinel.config import settings
from tests.conftest import unique_email


pytestmark = pytest.mark.asyncio


def _from_ip(ip: str) -> dict:
    return {"X-Forwarded-For": ip}


async def _fail(client, email: str, ip: str, times: int):
    for _ in range(times):
        response = await client.post(
            "/auth/login",
            json={"email": email, "password": "wrong-password"},
            headers=_from_ip(ip),
        )
        assert response.status_code == 401


async def test_login_locks_after_threshold_failures_from_one_ip(client, verified_user):
    user = await verified_user()

    await _fail(client, user["email"], "10.1.0.1", settings.login_lockout_threshold)

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
        headers=_from_ip("10.1.0.1"),
    )
    assert response.status_code == 401


async def test_locked_response_is_identical_to_invalid_credentials(
    client, verified_user
):
    user = await verified_user()
    threshold = settings.login_lockout_threshold

    baseline = await client.post(
        "/auth/login", json={"email": user["email"], "password": "wrong-password"}
    )

    await _fail(client, user["email"], "127.0.0.1", threshold - 1)

    locked_response = await client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
    )

    assert locked_response.status_code == baseline.status_code
    assert locked_response.json() == baseline.json()


async def test_attacker_cannot_lock_the_owner_out_from_another_ip(
    client, verified_user
):
    user = await verified_user()

    await _fail(client, user["email"], "203.0.113.7", settings.login_lockout_threshold)

    owner = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
        headers=_from_ip("198.51.100.20"),
    )

    assert owner.status_code == 200


async def test_successful_login_resets_failure_count(
    client, verified_user, monkeypatch
):
    monkeypatch.setattr(settings, "login_rate_limit", 20)

    user = await verified_user()
    threshold = settings.login_lockout_threshold

    await _fail(client, user["email"], "127.0.0.1", threshold - 1)

    success = await client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    assert success.status_code == 200

    await _fail(client, user["email"], "127.0.0.1", threshold - 1)

    still_works = await client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    assert still_works.status_code == 200


async def test_lockout_does_not_affect_other_accounts(client, verified_user):
    victim = await verified_user()
    bystander = await verified_user()

    await _fail(client, victim["email"], "10.1.0.1", settings.login_lockout_threshold)

    bystander_response = await client.post(
        "/auth/login",
        json={"email": bystander["email"], "password": bystander["password"]},
        headers=_from_ip("10.1.0.1"),
    )

    assert bystander_response.status_code == 200


async def test_unverified_and_unknown_accounts_never_lock(
    client, register, redis, monkeypatch
):
    monkeypatch.setattr(settings, "login_rate_limit", 20)

    email, _, _ = await register()

    for _ in range(settings.login_lockout_threshold + 2):
        await client.post("/auth/login", json={"email": email, "password": "wrong"})

    unknown_email = unique_email()
    for _ in range(settings.login_lockout_threshold + 2):
        await client.post(
            "/auth/login", json={"email": unknown_email, "password": "wrong"}
        )

    assert not any(
        k.startswith("login_lockout:") or k.startswith("login_failures:")
        for k in redis.storage
    )
