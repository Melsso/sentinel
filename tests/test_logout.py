import pytest


@pytest.mark.asyncio
async def test_logout_revokes_refresh_token(client):
    await client.post(
        "/auth/register",
        json={
            "email": "logout@example.com",
            "password": "Password123!",
        },
    )

    login = await client.post(
        "/auth/login",
        json={
            "email": "logout@example.com",
            "password": "Password123!",
        },
    )

    refresh_token = login.json()["refresh_token"]

    logout = await client.post(
        "/auth/logout",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert logout.status_code == 204

    refresh = await client.post(
        "/auth/refresh",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert refresh.status_code == 401
