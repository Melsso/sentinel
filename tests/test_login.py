import pytest

from sentinel.config import settings
from sentinel.database.models import AuthProvider
from tests.conftest import decode_token, unique_email

pytestmark = pytest.mark.asyncio


async def test_login_success(client, verified_user):
    user = await verified_user()

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


async def test_login_wrong_password(client, verified_user):
    user = await verified_user()

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": "not-the-password"},
    )

    assert response.status_code == 401


async def test_login_unknown_email(client):
    response = await client.post(
        "/auth/login",
        json={"email": unique_email(), "password": "Password123!"},
    )

    assert response.status_code == 401


async def test_login_unverified_user_rejected(client, register):
    email, password, resp = await register()
    assert resp.status_code == 201

    response = await client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )

    assert response.status_code == 401


async def test_login_deleted_user(client, verified_user, update_user):
    user = await verified_user()
    await update_user(user["id"], is_deleted=True)

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )

    assert response.status_code == 401


async def test_login_oauth_account_has_no_password(client, make_db_user):
    oauth_user = await make_db_user(
        provider=AuthProvider.GOOGLE,
        provider_user_id="google-oauth-subject-id",
        password_hash=None,
        is_verified=True,
    )

    response = await client.post(
        "/auth/login",
        json={"email": oauth_user.email, "password": "anything-at-all"},
    )

    assert response.status_code == 401


async def test_login_missing_password_hash(client, make_db_user):
    user = await make_db_user(
        provider=AuthProvider.LOCAL,
        password_hash=None,
        is_verified=True,
    )

    response = await client.post(
        "/auth/login",
        json={"email": user.email, "password": "anything-at-all"},
    )

    assert response.status_code == 401


async def test_login_access_token_payload(client, verified_user):
    user = await verified_user()

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200

    payload = decode_token(response.json()["access_token"])

    assert payload["sub"] == user["id"]
    assert "iat" in payload
    assert "exp" in payload
    assert payload["exp"] > payload["iat"]


async def test_login_refresh_token_persisted(
    client, verified_user, get_session_for_token
):
    user = await verified_user()

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200

    refresh_token = response.json()["refresh_token"]
    session = await get_session_for_token(refresh_token)

    assert session is not None
    assert str(session.user_id) == user["id"]


async def test_login_creates_session(client, verified_user, sessions_for_user):
    user = await verified_user()

    before = await sessions_for_user(user["id"])
    assert len(before) == 0

    response = await client.post(
        "/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200

    after = await sessions_for_user(user["id"])
    assert len(after) == 1

    session = after[0]
    assert session.revoked_at is None

    expected_lifetime = settings.refresh_token_expire_days * 24 * 3600
    actual_lifetime = (session.expires_at - session.created_at).total_seconds()
    assert abs(actual_lifetime - expected_lifetime) < 5
