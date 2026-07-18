import logging

import pytest

from tests.conftest import unique_email


pytestmark = pytest.mark.asyncio


def _events(caplog, name="sentinel.audit"):
    return [r for r in caplog.records if r.name == name]


async def test_register_success_is_logged(client, caplog):
    with caplog.at_level(logging.INFO, logger="sentinel.audit"):
        response = await client.post(
            "/auth/register",
            json={"email": unique_email(), "password": "Password123!"},
        )

    records = _events(caplog)
    assert any(r.event == "register_success" for r in records)

    record = next(r for r in records if r.event == "register_success")
    assert record.user_id == response.json()["id"]
    assert record.levelname == "INFO"
    assert hasattr(record, "ip")


async def test_register_duplicate_is_logged_as_warning(client, register, caplog):
    email, password, _ = await register()

    with caplog.at_level(logging.INFO, logger="sentinel.audit"):
        await client.post("/auth/register", json={"email": email, "password": password})

    records = _events(caplog)
    record = next(r for r in records if r.event == "register_failed")
    assert record.levelname == "WARNING"
    assert record.reason == "email_already_exists"


async def test_login_success_and_failure_are_logged(client, verified_user, caplog):
    user = await verified_user()

    with caplog.at_level(logging.INFO, logger="sentinel.audit"):
        await client.post(
            "/auth/login", json={"email": user["email"], "password": "wrong-password"}
        )
        await client.post(
            "/auth/login", json={"email": user["email"], "password": user["password"]}
        )

    records = _events(caplog)

    failed = next(r for r in records if r.event == "login_failed")
    assert failed.levelname == "WARNING"
    assert failed.reason == "invalid_credentials"

    succeeded = next(r for r in records if r.event == "login_success")
    assert succeeded.user_id == user["id"]


async def test_logout_all_logs_session_count(
    client, verified_user, login, auth_headers, caplog
):
    user = await verified_user()
    await login(user)
    tokens = await login(user)

    with caplog.at_level(logging.INFO, logger="sentinel.audit"):
        await client.post(
            "/auth/logout-all",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )

    record = next(r for r in _events(caplog) if r.event == "logout_all_success")
    assert record.user_id == user["id"]
    assert record.sessions_revoked == 2


async def test_forgot_password_logs_whether_account_was_found(
    client, verified_user, caplog
):
    user = await verified_user()

    with caplog.at_level(logging.INFO, logger="sentinel.audit"):
        await client.post("/auth/forgot-password", json={"email": user["email"]})
        await client.post("/auth/forgot-password", json={"email": unique_email()})

    records = [r for r in _events(caplog) if r.event == "password_reset_requested"]
    assert len(records) == 2
    assert any(r.account_found is True for r in records)
    assert any(r.account_found is False for r in records)


async def test_rate_limit_exceeded_is_logged(client, verified_user, caplog):
    from sentinel.config import settings

    user = await verified_user()

    with caplog.at_level(logging.INFO, logger="sentinel.audit"):
        for _ in range(settings.login_rate_limit + 1):
            await client.post(
                "/auth/login",
                json={"email": user["email"], "password": "wrong-password"},
            )

    record = next(r for r in _events(caplog) if r.event == "rate_limit_exceeded")
    assert record.levelname == "WARNING"
    assert record.scope == "login"


async def test_no_secrets_leak_into_audit_logs(client, verified_user, login, caplog):
    user = await verified_user()

    with caplog.at_level(logging.INFO, logger="sentinel.audit"):
        tokens = await login(user)
        await client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "current_password": user["password"],
                "new_password": "NewPassword123!",
            },
        )

    for record in _events(caplog):
        for value in vars(record).values():
            if isinstance(value, str):
                assert user["password"] not in value
                assert "NewPassword123!" not in value
                assert tokens["access_token"] not in value
                assert tokens["refresh_token"] not in value
