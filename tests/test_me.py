import pytest

pytestmark = pytest.mark.asyncio


async def test_me_success(client, verified_user, auth_headers):
    user = await verified_user()
    headers = await auth_headers(user)

    response = await client.get("/auth/me", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == user["id"]
    assert data["email"] == user["email"]


async def test_me_no_credentials(client):
    response = await client.get("/auth/me")

    assert response.status_code == 401


async def test_me_malformed_header(client):
    response = await client.get(
        "/auth/me", headers={"Authorization": "not-a-bearer-token"}
    )

    assert response.status_code == 401


async def test_me_garbage_token(client):
    response = await client.get(
        "/auth/me", headers={"Authorization": "Bearer this.is.not-a-jwt"}
    )

    assert response.status_code == 401


async def test_me_refresh_token_rejected(client, verified_user, login):
    user = await verified_user()
    tokens = await login(user)

    response = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"}
    )

    assert response.status_code == 401


async def test_me_deleted_user_rejected(
    client, verified_user, auth_headers, update_user
):
    user = await verified_user()
    headers = await auth_headers(user)

    await update_user(user["id"], is_deleted=True)

    response = await client.get("/auth/me", headers=headers)

    assert response.status_code == 401
