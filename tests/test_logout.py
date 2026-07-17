import pytest

pytestmark = pytest.mark.asyncio


async def _login(client, user):
    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200
    return response.json()


async def test_logout_success(client, verified_user, get_session_for_token):
    user = await verified_user()
    tokens = await _login(client, user)

    response = await client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 204

    session = await get_session_for_token(tokens["refresh_token"])
    assert session is not None
    assert session.revoked_at is not None


async def test_logout_is_idempotent(client, verified_user):
    user = await verified_user()
    tokens = await _login(client, user)

    first = await client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    second = await client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert first.status_code == 204
    assert second.status_code == 204


async def test_refresh_fails_after_logout(client, verified_user):
    user = await verified_user()
    tokens = await _login(client, user)

    logout = await client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert logout.status_code == 204

    refresh = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert refresh.status_code == 401


async def test_logout_unknown_token(client):
    response = await client.post(
        "/auth/logout",
        json={"refresh_token": "this-token-was-never-issued"},
    )

    assert response.status_code == 401
