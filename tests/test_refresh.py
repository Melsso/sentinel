from datetime import timedelta

import pytest

from sentinel.core.time import utcnow

pytestmark = pytest.mark.asyncio


async def _login(client, user):
    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200
    return response.json()


async def test_refresh_success(client, verified_user):
    user = await verified_user()
    tokens = await _login(client, user)

    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


async def test_refresh_rotates_token(client, verified_user, get_session_for_token):
    user = await verified_user()
    tokens = await _login(client, user)

    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert response.status_code == 200

    new_refresh_token = response.json()["refresh_token"]
    assert new_refresh_token != tokens["refresh_token"]

    assert (await get_session_for_token(tokens["refresh_token"])) is None
    assert (await get_session_for_token(new_refresh_token)) is not None


async def test_refresh_old_token_invalid_after_rotation(client, verified_user):
    user = await verified_user()
    tokens = await _login(client, user)

    first_refresh = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert first_refresh.status_code == 200

    reuse_old_token = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert reuse_old_token.status_code == 401


async def test_refresh_unknown_token(client):
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": "this-token-does-not-exist"},
    )

    assert response.status_code == 401


async def test_refresh_revoked_session(client, verified_user):
    user = await verified_user()
    tokens = await _login(client, user)

    logout = await client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert logout.status_code == 204

    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 401


async def test_refresh_expired_session(
    client, verified_user, get_session_for_token, db_session
):
    user = await verified_user()
    tokens = await _login(client, user)

    session = await get_session_for_token(tokens["refresh_token"])
    session.expires_at = utcnow() - timedelta(minutes=1)
    await db_session.commit()

    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 401


async def test_refresh_deleted_user(client, verified_user, update_user):
    user = await verified_user()
    tokens = await _login(client, user)

    await update_user(user["id"], is_deleted=True)

    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 401
