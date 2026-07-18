import pytest

from sentinel.core.security import password_hasher


pytestmark = pytest.mark.asyncio


async def test_change_password_success(client, verified_user, auth_headers, get_user):
    user = await verified_user()
    headers = await auth_headers(user)

    response = await client.post(
        "/auth/change-password",
        headers=headers,
        json={"current_password": user["password"], "new_password": "NewPassword123!"},
    )

    assert response.status_code == 200

    updated_user = await get_user(user["id"])
    assert password_hasher.verify("NewPassword123!", updated_user.password_hash)


async def test_change_password_wrong_current_password(
    client, verified_user, auth_headers
):
    user = await verified_user()
    headers = await auth_headers(user)

    response = await client.post(
        "/auth/change-password",
        headers=headers,
        json={"current_password": "totally-wrong", "new_password": "NewPassword123!"},
    )

    assert response.status_code == 401


async def test_change_password_requires_auth(client):
    response = await client.post(
        "/auth/change-password",
        json={"current_password": "whatever", "new_password": "NewPassword123!"},
    )

    assert response.status_code == 401


async def test_change_password_revokes_existing_sessions(
    client, verified_user, login, auth_headers, sessions_for_user
):
    user = await verified_user()
    other_device_tokens = await login(user)
    headers = await auth_headers(user)

    response = await client.post(
        "/auth/change-password",
        headers=headers,
        json={"current_password": user["password"], "new_password": "NewPassword123!"},
    )
    assert response.status_code == 200

    sessions = await sessions_for_user(user["id"])
    assert all(s.revoked_at is not None for s in sessions)

    refresh = await client.post(
        "/auth/refresh",
        json={"refresh_token": other_device_tokens["refresh_token"]},
    )
    assert refresh.status_code == 401


async def test_change_password_can_login_with_new_password(
    client, verified_user, auth_headers
):
    user = await verified_user()
    headers = await auth_headers(user)

    await client.post(
        "/auth/change-password",
        headers=headers,
        json={"current_password": user["password"], "new_password": "NewPassword123!"},
    )

    login_response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": "NewPassword123!"},
    )

    assert login_response.status_code == 200

    old_password_login = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert old_password_login.status_code == 401
