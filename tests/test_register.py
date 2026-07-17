import pytest


@pytest.mark.asyncio
async def test_register_success(client):
    response = await client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "password": "Password123!",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["email"] == "test@example.com"
    assert "password_hash" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    payload = {
        "email": "duplicate@example.com",
        "password": "Password123!",
    }

    first = await client.post(
        "/auth/register",
        json=payload,
    )

    second = await client.post(
        "/auth/register",
        json=payload,
    )

    assert first.status_code == 201
    assert second.status_code == 409
