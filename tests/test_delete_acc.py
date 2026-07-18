import pytest


pytestmark = pytest.mark.asyncio


async def test_delete_account_success(client, verified_user, auth_headers, get_user):
    user = await verified_user()
    headers = await auth_headers(user)

    response = await client.request(
        "DELETE", "/auth/me", headers=headers, json={"password": user["password"]}
    )

    assert response.status_code == 204

    deleted_user = await get_user(user["id"])
    assert deleted_user.is_deleted is True


async def test_delete_account_wrong_password(
    client, verified_user, auth_headers, get_user
):
    user = await verified_user()
    headers = await auth_headers(user)

    response = await client.request(
        "DELETE", "/auth/me", headers=headers, json={"password": "wrong"}
    )

    assert response.status_code == 401

    unchanged_user = await get_user(user["id"])
    assert unchanged_user.is_deleted is False


async def test_delete_account_requires_auth(client):
    response = await client.request("DELETE", "/auth/me", json={"password": "whatever"})

    assert response.status_code == 401


async def test_delete_account_revokes_sessions(
    client, verified_user, login, auth_headers, sessions_for_user
):
    user = await verified_user()
    other_device_tokens = await login(user)
    headers = await auth_headers(user)

    response = await client.request(
        "DELETE", "/auth/me", headers=headers, json={"password": user["password"]}
    )
    assert response.status_code == 204

    sessions = await sessions_for_user(user["id"])
    assert all(s.revoked_at is not None for s in sessions)

    refresh = await client.post(
        "/auth/refresh",
        json={"refresh_token": other_device_tokens["refresh_token"]},
    )
    assert refresh.status_code == 401


async def test_deleted_account_cannot_login(client, verified_user, auth_headers):
    user = await verified_user()
    headers = await auth_headers(user)

    await client.request(
        "DELETE", "/auth/me", headers=headers, json={"password": user["password"]}
    )

    login_response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )

    assert login_response.status_code == 401


async def test_deleted_account_blocks_reregistration(
    client, verified_user, auth_headers
):
    user = await verified_user()
    headers = await auth_headers(user)

    await client.request(
        "DELETE", "/auth/me", headers=headers, json={"password": user["password"]}
    )

    register_response = await client.post(
        "/auth/register",
        json={"email": user["email"], "password": "AnotherPassword123!"},
    )

    assert register_response.status_code == 409
