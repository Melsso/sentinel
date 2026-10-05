from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest

from sentinel.config import settings
from sentinel.core.time import utcnow
from tests.conftest import decode_token

pytestmark = pytest.mark.asyncio


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _refresh(client, token: str):
    return await client.post("/auth/refresh", json={"refresh_token": token})


def _forge(drop: tuple[str, ...] = (), **overrides) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(uuid4()),
        "sid": str(uuid4()),
        "typ": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    for key in drop:
        claims.pop(key)
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def test_access_token_claims(verified_user, login):
    user = await verified_user()
    tokens = await login(user)

    claims = decode_token(tokens["access_token"])

    assert claims["sub"] == user["id"]
    assert claims["typ"] == "access"
    assert claims["iss"] == settings.jwt_issuer
    assert claims["aud"] == settings.jwt_audience
    assert claims["sid"]


async def test_replayed_refresh_token_revokes_the_session(
    client, verified_user, login, get_session_for_token
):
    user = await verified_user()
    first = await login(user)

    rotated = (await _refresh(client, first["refresh_token"])).json()

    replay = await _refresh(client, first["refresh_token"])
    assert replay.status_code == 401

    legit = await _refresh(client, rotated["refresh_token"])
    assert legit.status_code == 401

    session = await get_session_for_token(rotated["refresh_token"])
    assert session.revoked_at is not None

    me = await client.get("/auth/me", headers=_bearer(rotated["access_token"]))
    assert me.status_code == 401


async def test_replaying_an_older_generation_also_revokes(client, verified_user, login):
    user = await verified_user()
    first = await login(user)

    second = (await _refresh(client, first["refresh_token"])).json()
    third = (await _refresh(client, second["refresh_token"])).json()

    assert (await _refresh(client, first["refresh_token"])).status_code == 401
    assert (await _refresh(client, third["refresh_token"])).status_code == 401


async def test_refresh_never_extends_past_absolute_lifetime(
    client, verified_user, login, get_session_for_token, db_session
):
    user = await verified_user()
    tokens = await login(user)

    session = await get_session_for_token(tokens["refresh_token"])
    cap = utcnow() + timedelta(hours=1)
    session.absolute_expires_at = cap
    await db_session.commit()

    response = await _refresh(client, tokens["refresh_token"])
    assert response.status_code == 200

    refreshed = await get_session_for_token(response.json()["refresh_token"])
    assert refreshed.expires_at <= cap


async def test_refresh_rejected_after_absolute_lifetime(
    client, verified_user, login, get_session_for_token, db_session
):
    user = await verified_user()
    tokens = await login(user)

    session = await get_session_for_token(tokens["refresh_token"])
    session.absolute_expires_at = utcnow() - timedelta(minutes=1)
    await db_session.commit()

    assert (await _refresh(client, tokens["refresh_token"])).status_code == 401


async def test_access_token_dies_on_logout(client, verified_user, login):
    user = await verified_user()
    tokens = await login(user)

    assert (
        await client.get("/auth/me", headers=_bearer(tokens["access_token"]))
    ).status_code == 200

    await client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})

    assert (
        await client.get("/auth/me", headers=_bearer(tokens["access_token"]))
    ).status_code == 401


async def test_access_token_dies_on_password_change(
    client, verified_user, login, auth_headers
):
    user = await verified_user()
    other_device = await login(user)
    headers = await auth_headers(user)

    response = await client.post(
        "/auth/change-password",
        headers=headers,
        json={"current_password": user["password"], "new_password": "NewPassword123!"},
    )
    assert response.status_code == 200

    me = await client.get("/auth/me", headers=_bearer(other_device["access_token"]))
    assert me.status_code == 401


async def test_access_token_dies_on_logout_all(client, verified_user, login):
    user = await verified_user()
    other_device = await login(user)
    tokens = await login(user)

    await client.post("/auth/logout-all", headers=_bearer(tokens["access_token"]))

    me = await client.get("/auth/me", headers=_bearer(other_device["access_token"]))
    assert me.status_code == 401


@pytest.mark.parametrize(
    "token_kwargs",
    [
        {"aud": "someone-else"},
        {"iss": "someone-else"},
        {"typ": "refresh"},
        {"drop": ("sid",)},
        {"drop": ("typ",)},
    ],
)
async def test_malformed_or_foreign_tokens_are_rejected(client, token_kwargs):
    token = _forge(**token_kwargs)

    response = await client.get("/auth/me", headers=_bearer(token))

    assert response.status_code == 401


async def test_validly_signed_token_without_a_session_is_rejected(client):
    response = await client.get("/auth/me", headers=_bearer(_forge()))

    assert response.status_code == 401
