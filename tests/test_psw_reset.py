import pytest

from sentinel.core.security import password_hasher
from sentinel.database.models import AuthProvider
from tests.conftest import unique_email


pytestmark = pytest.mark.asyncio


async def test_forgot_password_known_email_stores_token(
    client, verified_user, find_password_reset_token
):
    user = await verified_user()

    response = await client.post("/auth/forgot-password", json={"email": user["email"]})

    assert response.status_code == 200
    token = find_password_reset_token(user["id"])
    assert token is not None


async def test_forgot_password_unknown_email_same_response(client, redis):
    response = await client.post(
        "/auth/forgot-password", json={"email": unique_email()}
    )

    assert response.status_code == 200
    assert response.json()["message"] == (
        "If that email is registered, a password reset link has been sent."
    )
    assert not any(k.startswith("password_reset:") for k in redis.storage)


async def test_forgot_password_oauth_account_no_token(
    client, make_db_user, find_password_reset_token
):
    user = await make_db_user(provider=AuthProvider.GOOGLE, provider_user_id="sub-123")

    response = await client.post("/auth/forgot-password", json={"email": user.email})

    assert response.status_code == 200
    assert find_password_reset_token(user.id) is None


async def test_forgot_password_deleted_account_no_token(
    client, make_db_user, find_password_reset_token
):
    user = await make_db_user(
        password_hash=password_hasher.hash("Password123!"),
        is_deleted=True,
    )

    response = await client.post("/auth/forgot-password", json={"email": user.email})

    assert response.status_code == 200
    assert find_password_reset_token(user.id) is None


async def test_reset_password_success(
    client, verified_user, find_password_reset_token, get_user
):
    user = await verified_user()
    await client.post("/auth/forgot-password", json={"email": user["email"]})
    token = find_password_reset_token(user["id"])

    response = await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "NewPassword123!"},
    )

    assert response.status_code == 200

    updated_user = await get_user(user["id"])
    assert password_hasher.verify("NewPassword123!", updated_user.password_hash)
    assert not password_hasher.verify(user["password"], updated_user.password_hash)


async def test_reset_password_invalid_token(client):
    response = await client.post(
        "/auth/reset-password",
        json={"token": "not-a-real-token", "new_password": "NewPassword123!"},
    )

    assert response.status_code == 400


async def test_reset_password_token_is_one_time_use(
    client, verified_user, find_password_reset_token
):
    user = await verified_user()
    await client.post("/auth/forgot-password", json={"email": user["email"]})
    token = find_password_reset_token(user["id"])

    first = await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "NewPassword123!"},
    )
    assert first.status_code == 200

    second = await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "AnotherPassword123!"},
    )
    assert second.status_code == 400


async def test_reset_password_revokes_existing_sessions(
    client, verified_user, login, find_password_reset_token, sessions_for_user
):
    user = await verified_user()
    tokens = await login(user)

    await client.post("/auth/forgot-password", json={"email": user["email"]})
    reset_token = find_password_reset_token(user["id"])
    response = await client.post(
        "/auth/reset-password",
        json={"token": reset_token, "new_password": "NewPassword123!"},
    )
    assert response.status_code == 200

    sessions = await sessions_for_user(user["id"])
    assert all(s.revoked_at is not None for s in sessions)

    refresh = await client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh.status_code == 401


async def test_reset_password_can_login_with_new_password(
    client, verified_user, find_password_reset_token
):
    user = await verified_user()
    await client.post("/auth/forgot-password", json={"email": user["email"]})
    token = find_password_reset_token(user["id"])

    await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "NewPassword123!"},
    )

    login_response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": "NewPassword123!"},
    )

    assert login_response.status_code == 200
