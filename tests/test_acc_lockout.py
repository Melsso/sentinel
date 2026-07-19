import pytest

from sentinel.config import settings
from tests.conftest import unique_email


pytestmark = pytest.mark.asyncio


async def test_account_locks_after_threshold_failures(client, verified_user):
    user = await verified_user()
    threshold = settings.login_lockout_threshold

    for _ in range(threshold):
        response = await client.post(
            "/auth/login", json={"email": user["email"], "password": "wrong-password"}
        )
        assert response.status_code == 401

    response = await client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
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

    for _ in range(threshold - 1):
        await client.post(
            "/auth/login", json={"email": user["email"], "password": "wrong-password"}
        )

    locked_response = await client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
    )

    assert locked_response.status_code == baseline.status_code
    assert locked_response.json() == baseline.json()


async def test_lockout_persists_across_different_ips(client, verified_user):
    user = await verified_user()
    threshold = settings.login_lockout_threshold

    for i in range(threshold):
        await client.post(
            "/auth/login",
            json={"email": user["email"], "password": "wrong-password"},
            headers={"X-Forwarded-For": f"10.1.0.{i}"},
        )

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
        headers={"X-Forwarded-For": "10.1.0.99"},
    )

    assert response.status_code == 401


async def test_successful_login_resets_failure_count(
    client, verified_user, monkeypatch
):
    monkeypatch.setattr(settings, "login_rate_limit", 20)

    user = await verified_user()
    threshold = settings.login_lockout_threshold

    for _ in range(threshold - 1):
        await client.post(
            "/auth/login", json={"email": user["email"], "password": "wrong-password"}
        )

    success = await client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    assert success.status_code == 200

    for _ in range(threshold - 1):
        await client.post(
            "/auth/login", json={"email": user["email"], "password": "wrong-password"}
        )

    still_works = await client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
    )
    assert still_works.status_code == 200


async def test_lockout_does_not_affect_other_accounts(client, verified_user):
    victim = await verified_user()
    bystander = await verified_user()
    threshold = settings.login_lockout_threshold

    for _ in range(threshold):
        await client.post(
            "/auth/login", json={"email": victim["email"], "password": "wrong-password"}
        )

    bystander_response = await client.post(
        "/auth/login",
        json={"email": bystander["email"], "password": bystander["password"]},
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
