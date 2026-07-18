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


async def test_logout_all_revokes_every_session(
    client, verified_user, login, auth_headers, sessions_for_user
):
    user = await verified_user()

    await login(user)
    await login(user)
    tokens = await login(user)

    sessions_before = await sessions_for_user(user["id"])
    assert len(sessions_before) == 3
    assert all(s.revoked_at is None for s in sessions_before)

    response = await client.post(
        "/auth/logout-all",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Revoked 3 active session(s)."

    sessions_after = await sessions_for_user(user["id"])
    assert all(s.revoked_at is not None for s in sessions_after)


async def test_logout_all_invalidates_refresh_tokens(client, verified_user, login):
    user = await verified_user()
    tokens = await login(user)

    await client.post(
        "/auth/logout-all",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    refresh = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert refresh.status_code == 401


async def test_logout_all_requires_auth(client):
    response = await client.post("/auth/logout-all")

    assert response.status_code == 401


async def test_logout_all_no_sessions(client, verified_user, auth_headers):
    user = await verified_user()
    headers = await auth_headers(user)

    first = await client.post("/auth/logout-all", headers=headers)
    assert first.status_code == 200
    assert first.json()["message"] == "Revoked 1 active session(s)."

    second = await client.post("/auth/logout-all", headers=headers)
    assert second.status_code == 200
    assert second.json()["message"] == "Revoked 0 active session(s)."
