import pytest

pytestmark = pytest.mark.asyncio


async def test_verify_email_success(
    client, register, find_verification_token, get_user
):
    _, _, resp = await register()
    user_id = resp.json()["id"]
    token = find_verification_token(user_id)

    response = await client.post("/auth/verify-email", json={"token": token})

    assert response.status_code == 200
    assert response.json()["is_verified"] is True

    user = await get_user(user_id)
    assert user.is_verified is True


async def test_verify_email_invalid_token(client):
    response = await client.post(
        "/auth/verify-email", json={"token": "not-a-real-token"}
    )

    assert response.status_code == 400


async def test_verify_email_expired_token(
    client, register, find_verification_token, redis
):
    _, _, resp = await register()
    user_id = resp.json()["id"]
    token = find_verification_token(user_id)

    redis.storage.pop(f"email_verify:{token}")

    response = await client.post("/auth/verify-email", json={"token": token})

    assert response.status_code == 400


async def test_verify_email_token_is_one_time_use(
    client, register, find_verification_token
):
    _, _, resp = await register()
    user_id = resp.json()["id"]
    token = find_verification_token(user_id)

    first = await client.post("/auth/verify-email", json={"token": token})
    assert first.status_code == 200

    second = await client.post("/auth/verify-email", json={"token": token})
    assert second.status_code == 400


async def test_verify_email_cleans_up_redis(
    client, register, find_verification_token, redis
):
    _, _, resp = await register()
    user_id = resp.json()["id"]
    token = find_verification_token(user_id)

    assert f"email_verify:{token}" in redis.storage

    response = await client.post("/auth/verify-email", json={"token": token})
    assert response.status_code == 200

    assert f"email_verify:{token}" not in redis.storage


async def test_verify_email_updates_user_record(
    client, register, find_verification_token, get_user
):
    _, _, resp = await register()
    user_id = resp.json()["id"]

    user_before = await get_user(user_id)
    assert user_before.is_verified is False

    token = find_verification_token(user_id)
    response = await client.post("/auth/verify-email", json={"token": token})
    assert response.status_code == 200

    user_after = await get_user(user_id)
    assert user_after.is_verified is True
    assert user_after.updated_at >= user_before.updated_at
