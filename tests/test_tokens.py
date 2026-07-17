import pytest


@pytest.mark.asyncio
async def test_refresh_token_rotation(client, verified_user):
    user = await verified_user()

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )

    assert response.status_code == 200

    refresh_token = response.json()["refresh_token"]
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["refresh_token"] != refresh_token
    assert "access_token" in data


@pytest.mark.asyncio
async def test_invalid_refresh_token(client):
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": "invalid"},
    )

    assert response.status_code == 401
