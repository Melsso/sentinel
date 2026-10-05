import pytest
from sqlalchemy import func, select

from sentinel.core.security import hash_token, password_hasher
from sentinel.database.models import User
from sentinel.routes.auth import REGISTER_MESSAGE
from sentinel.schemas.auth import RegisterRequest
from sentinel.services.auth import register_user
from tests.conftest import unique_email

pytestmark = pytest.mark.asyncio


async def _count_users(db_session, email: str) -> int:
    return await db_session.scalar(
        select(func.count()).select_from(User).where(User.email == email.lower())
    )


async def test_register_success(client, get_user_by_email):
    email = unique_email()

    response = await client.post(
        "/auth/register",
        json={"email": email, "password": "Password123!"},
    )

    assert response.status_code == 202
    assert response.json() == {"message": REGISTER_MESSAGE}

    user = await get_user_by_email(email)
    assert user is not None
    assert user.is_verified is False
    assert user.is_deleted is False


async def test_register_duplicate_email_is_indistinguishable(
    client, verified_user, db_session
):
    existing = await verified_user()

    fresh = await client.post(
        "/auth/register",
        json={"email": unique_email(), "password": "Password123!"},
    )
    duplicate = await client.post(
        "/auth/register",
        json={"email": existing["email"], "password": "Password123!"},
    )

    assert duplicate.status_code == fresh.status_code == 202
    assert duplicate.json() == fresh.json()
    assert await _count_users(db_session, existing["email"]) == 1


async def test_register_duplicate_notifies_owner_without_a_verification_link(
    client, verified_user, fake_email
):
    existing = await verified_user()
    fake_email.sent.clear()

    await client.post(
        "/auth/register",
        json={"email": existing["email"], "password": "Password123!"},
    )

    assert len(fake_email.sent) == 1
    assert fake_email.sent[0]["to"] == existing["email"]
    assert "verify-email?token=" not in fake_email.sent[0]["body"]


async def test_register_again_before_verifying_resends_verification(
    client, register, fake_email
):
    email, password, _ = await register()
    fake_email.sent.clear()

    response = await client.post(
        "/auth/register", json={"email": email, "password": password}
    )

    assert response.status_code == 202
    assert len(fake_email.sent) == 1
    assert "verify-email?token=" in fake_email.sent[0]["body"]


async def test_register_email_normalization(client, db_session, get_user_by_email):
    raw_email = f"MiXed.Case.{unique_email('n')}"

    response = await client.post(
        "/auth/register",
        json={"email": raw_email, "password": "Password123!"},
    )
    assert response.status_code == 202

    user = await get_user_by_email(raw_email)
    assert user is not None
    assert user.email == raw_email.strip().lower()

    duplicate = await client.post(
        "/auth/register",
        json={"email": raw_email.upper(), "password": "Password123!"},
    )
    assert duplicate.status_code == 202
    assert await _count_users(db_session, raw_email) == 1


async def test_register_password_is_hashed(client, get_user_by_email):
    plain_password = "Password123!"
    email = unique_email()

    response = await client.post(
        "/auth/register",
        json={"email": email, "password": plain_password},
    )
    assert response.status_code == 202

    user = await get_user_by_email(email)
    assert user.password_hash is not None
    assert user.password_hash != plain_password
    assert password_hasher.verify(plain_password, user.password_hash)


async def test_register_response_exposes_no_account_data(client):
    response = await client.post(
        "/auth/register",
        json={"email": unique_email(), "password": "Password123!"},
    )

    assert set(response.json().keys()) == {"message"}


async def test_register_stores_only_a_hash_of_the_verification_token(
    client, get_user_by_email, find_verification_token, redis
):
    email = unique_email()
    await client.post(
        "/auth/register", json={"email": email, "password": "Password123!"}
    )

    user = await get_user_by_email(email)
    token = find_verification_token(user.id)

    assert token is not None
    assert redis.storage[f"email_verify:{hash_token(token)}"] == str(user.id)
    assert not any(token in key for key in redis.storage)


async def test_register_race_on_unique_email_is_treated_as_existing(
    db_session, make_db_user, fake_email, redis, monkeypatch
):
    existing = await make_db_user(
        password_hash=password_hasher.hash("Password123!"), is_verified=True
    )

    real_scalar = db_session.scalar
    calls = {"count": 0}

    async def flaky_scalar(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return None
        return await real_scalar(*args, **kwargs)

    monkeypatch.setattr(db_session, "scalar", flaky_scalar)

    result = await register_user(
        db_session, RegisterRequest(email=existing.email, password="Password123!")
    )

    assert result is None
    assert len(fake_email.sent) == 1
