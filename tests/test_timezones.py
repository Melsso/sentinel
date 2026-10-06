import pytest

pytestmark = pytest.mark.asyncio


async def test_stored_datetimes_are_timezone_aware(
    client, verified_user, login, get_user, sessions_for_user
):
    user = await verified_user()
    await login(user)

    db_user = await get_user(user["id"])
    assert db_user.created_at.tzinfo is not None
    assert db_user.updated_at.tzinfo is not None

    for session in await sessions_for_user(user["id"]):
        assert session.created_at.tzinfo is not None
        assert session.expires_at.tzinfo is not None
        assert session.absolute_expires_at.tzinfo is not None


async def test_api_datetimes_carry_a_utc_offset(client, verified_user, auth_headers):
    user = await verified_user()
    headers = await auth_headers(user)

    created_at = (await client.get("/auth/me", headers=headers)).json()["created_at"]

    assert created_at.endswith(("Z", "+00:00"))
