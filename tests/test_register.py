import pytest

from sentinel.core.security import password_hasher
from tests.conftest import unique_email

pytestmark = pytest.mark.asyncio


async def test_register_success(client, get_user):
    email = unique_email()

    response = await client.post(
        "/auth/register",
        json={"email": email, "password": "Password123!"},
    )

    assert response.status_code == 201

    data = response.json()
    assert data["email"] == email
    assert data["is_verified"] is False
    assert data["provider"] == "local"
    assert data["role"] == "user"
    assert "id" in data

    user = await get_user(data["id"])
    assert user is not None
    assert user.is_deleted is False


async def test_register_duplicate_email(client, register):
    email, password, first = await register()
    second = await client.post(
        "/auth/register", json={"email": email, "password": password}
    )

    assert first.status_code == 201
    assert second.status_code == 409


async def test_register_email_normalization(client, get_user):
    raw_email = f"MiXed.Case.{unique_email('n')}"

    response = await client.post(
        "/auth/register",
        json={"email": raw_email, "password": "Password123!"},
    )
    assert response.status_code == 201

    normalized = response.json()["email"]
    assert normalized == raw_email.strip().lower()

    user = await get_user(response.json()["id"])
    assert user.email == raw_email.strip().lower()

    duplicate = await client.post(
        "/auth/register",
        json={"email": normalized.upper(), "password": "Password123!"},
    )
    assert duplicate.status_code == 409


async def test_register_password_is_hashed(client, get_user):
    plain_password = "Password123!"

    response = await client.post(
        "/auth/register",
        json={"email": unique_email(), "password": plain_password},
    )
    assert response.status_code == 201

    user = await get_user(response.json()["id"])
    assert user.password_hash is not None
    assert user.password_hash != plain_password
    assert password_hasher.verify(plain_password, user.password_hash)


async def test_register_response_is_sanitized(client):
    response = await client.post(
        "/auth/register",
        json={"email": unique_email(), "password": "Password123!"},
    )
    assert response.status_code == 201

    data = response.json()
    assert "password_hash" not in data
    assert "password" not in data
    assert set(data.keys()) == {
        "id",
        "email",
        "provider",
        "role",
        "is_verified",
        "created_at",
        "updated_at",
    }


async def test_register_stores_verification_token(
    client, find_verification_token, redis
):
    response = await client.post(
        "/auth/register",
        json={"email": unique_email(), "password": "Password123!"},
    )
    assert response.status_code == 201

    user_id = response.json()["id"]
    token = find_verification_token(user_id)

    assert token is not None
    assert redis.storage[f"email_verify:{token}"] == user_id


async def test_register_with_email_of_soft_deleted_user(client, make_db_user):
    deleted_user = await make_db_user(
        password_hash=password_hasher.hash("Password123!"),
        is_verified=True,
        is_deleted=True,
    )

    response = await client.post(
        "/auth/register",
        json={"email": deleted_user.email, "password": "NewPassword123!"},
    )

    assert response.status_code == 409
