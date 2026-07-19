import uuid

import pytest


pytestmark = pytest.mark.asyncio


async def test_revoke_session_success(client, verified_user, login, auth_headers):
    user = await verified_user()
    await login(user)
    headers = await auth_headers(user)

    listed = await client.get("/auth/sessions", headers=headers)
    session_id = listed.json()[0]["id"]

    response = await client.delete(f"/auth/sessions/{session_id}", headers=headers)

    assert response.status_code == 204

    remaining = await client.get("/auth/sessions", headers=headers)
    remaining_ids = [s["id"] for s in remaining.json()]
    assert session_id not in remaining_ids


async def test_revoke_session_invalidates_its_refresh_token(
    client, verified_user, login, auth_headers, get_session_for_token
):
    user = await verified_user()
    tokens = await login(user)
    headers = await auth_headers(user)

    session = await get_session_for_token(tokens["refresh_token"])

    response = await client.delete(f"/auth/sessions/{session.id}", headers=headers)
    assert response.status_code == 204

    refresh = await client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 401


async def test_revoke_session_unknown_id(client, verified_user, auth_headers):
    user = await verified_user()
    headers = await auth_headers(user)

    response = await client.delete(f"/auth/sessions/{uuid.uuid4()}", headers=headers)

    assert response.status_code == 404


async def test_revoke_session_belonging_to_another_user(
    client, verified_user, login, auth_headers, get_session_for_token
):
    owner = await verified_user()
    other = await verified_user()

    owner_tokens = await login(owner)
    owner_session = await get_session_for_token(owner_tokens["refresh_token"])

    other_headers = await auth_headers(other)

    response = await client.delete(
        f"/auth/sessions/{owner_session.id}", headers=other_headers
    )

    assert response.status_code == 404

    owner_headers = await auth_headers(owner)
    owner_sessions = await client.get("/auth/sessions", headers=owner_headers)
    assert str(owner_session.id) in [s["id"] for s in owner_sessions.json()]


async def test_revoke_session_requires_auth(client):
    response = await client.delete(f"/auth/sessions/{uuid.uuid4()}")

    assert response.status_code == 401


async def test_revoke_session_leaves_other_sessions_active(
    client, verified_user, login, auth_headers
):
    user = await verified_user()
    await login(user)
    headers = await auth_headers(user)

    sessions = (await client.get("/auth/sessions", headers=headers)).json()
    assert len(sessions) == 2
    target_id = sessions[0]["id"]

    response = await client.delete(f"/auth/sessions/{target_id}", headers=headers)
    assert response.status_code == 204

    remaining = (await client.get("/auth/sessions", headers=headers)).json()
    assert len(remaining) == 1
    assert remaining[0]["id"] != target_id
