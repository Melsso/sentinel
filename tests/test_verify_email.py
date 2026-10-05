import pytest

from sentinel.core.security import hash_token

pytestmark = pytest.mark.asyncio


async def _register(register, get_user_by_email) -> str:
    email, _, resp = await register()
    assert resp.status_code == 202
    user = await get_user_by_email(email)
    return str(user.id)


async def test_verify_email_success(
    client, register, get_user_by_email, find_verification_token, get_user
):
    user_id = await _register(register, get_user_by_email)
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
    client, register, get_user_by_email, find_verification_token, redis
):
    user_id = await _register(register, get_user_by_email)
    token = find_verification_token(user_id)

    redis.storage.pop(f"email_verify:{hash_token(token)}")

    response = await client.post("/auth/verify-email", json={"token": token})

    assert response.status_code == 400


async def test_verify_email_token_is_one_time_use(
    client, register, get_user_by_email, find_verification_token
):
    user_id = await _register(register, get_user_by_email)
    token = find_verification_token(user_id)

    first = await client.post("/auth/verify-email", json={"token": token})
    assert first.status_code == 200

    second = await client.post("/auth/verify-email", json={"token": token})
    assert second.status_code == 400


async def test_verify_email_cleans_up_redis(
    client, register, get_user_by_email, find_verification_token, redis
):
    user_id = await _register(register, get_user_by_email)
    token = find_verification_token(user_id)
    key = f"email_verify:{hash_token(token)}"

    assert key in redis.storage

    response = await client.post("/auth/verify-email", json={"token": token})
    assert response.status_code == 200

    assert key not in redis.storage


async def test_verify_email_updates_user_record(
    client, register, get_user_by_email, find_verification_token, get_user
):
    user_id = await _register(register, get_user_by_email)

    user_before = await get_user(user_id)
    assert user_before.is_verified is False
    updated_before = user_before.updated_at

    token = find_verification_token(user_id)
    response = await client.post("/auth/verify-email", json={"token": token})
    assert response.status_code == 200

    user_after = await get_user(user_id)
    assert user_after.is_verified is True
    assert user_after.updated_at >= updated_before
