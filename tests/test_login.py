import pytest


@pytest.mark.asyncio
async def test_login_success(client):
    await client.post(
        "/auth/register",
        json={
            "email": "login@example.com",
            "password": "Password123!",
        },
    )

    response = await client.post(
        "/auth/login",
        json={
            "email": "login@example.com",
            "password": "Password123!",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await client.post(
        "/auth/register",
        json={
            "email": "wrong@example.com",
            "password": "Password123!",
        },
    )

    response = await client.post(
        "/auth/login",
        json={
            "email": "wrong@example.com",
            "password": "incorrect",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client):
    response = await client.post(
        "/auth/login",
        json={
            "email": "missing@example.com",
            "password": "Password123!",
        },
    )

    assert response.status_code == 401
