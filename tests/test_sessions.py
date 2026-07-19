from datetime import timedelta

import pytest

from sentinel.core.time import utcnow


pytestmark = pytest.mark.asyncio


async def test_list_sessions_returns_active_sessions(
    client, verified_user, login, auth_headers
):
    user = await verified_user()
    await login(user)
    await login(user)
    headers = await auth_headers(user)

    response = await client.get("/auth/sessions", headers=headers)

    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 3
    for session in sessions:
        assert set(session.keys()) == {"id", "created_at", "expires_at"}


async def test_list_sessions_excludes_revoked(
    client, verified_user, login, auth_headers
):
    user = await verified_user()
    tokens = await login(user)
    headers = await auth_headers(user)

    await client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})

    response = await client.get("/auth/sessions", headers=headers)

    assert response.status_code == 200
    assert len(response.json()) == 1


async def test_list_sessions_excludes_expired(
    client, verified_user, login, auth_headers, sessions_for_user, db_session
):
    user = await verified_user()
    await login(user)
    headers = await auth_headers(user)

    sessions = await sessions_for_user(user["id"])
    sessions[0].expires_at = utcnow() - timedelta(minutes=1)
    await db_session.commit()

    response = await client.get("/auth/sessions", headers=headers)

    assert response.status_code == 200
    assert len(response.json()) == 1


async def test_list_sessions_requires_auth(client):
    response = await client.get("/auth/sessions")

    assert response.status_code == 401


async def test_list_sessions_only_shows_own_sessions(
    client, verified_user, login, auth_headers
):
    user_a = await verified_user()
    user_b = await verified_user()

    await login(user_a)
    await login(user_a)
    headers_a = await auth_headers(user_a)

    await login(user_b)
    headers_b = await auth_headers(user_b)

    response_a = await client.get("/auth/sessions", headers=headers_a)
    response_b = await client.get("/auth/sessions", headers=headers_b)

    assert len(response_a.json()) == 3
    assert len(response_b.json()) == 2


async def test_list_sessions_most_recent_first(
    client, verified_user, login, auth_headers
):
    user = await verified_user()
    await login(user)
    await login(user)
    headers = await auth_headers(user)

    response = await client.get("/auth/sessions", headers=headers)

    timestamps = [s["created_at"] for s in response.json()]
    assert timestamps == sorted(timestamps, reverse=True)


async def test_list_sessions_reflects_logout_all(
    client, verified_user, login, auth_headers
):
    user = await verified_user()
    await login(user)
    await login(user)
    headers = await auth_headers(user)

    await client.post("/auth/logout-all", headers=headers)

    response = await client.get("/auth/sessions", headers=headers)

    assert response.status_code == 200
    assert response.json() == []
