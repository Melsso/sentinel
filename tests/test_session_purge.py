from datetime import timedelta

import pytest

from sentinel.config import settings
from sentinel.core.time import utcnow
from sentinel.services.auth import purge_stale_sessions

pytestmark = pytest.mark.asyncio


async def test_purge_removes_expired_and_long_revoked_sessions(
    verified_user, login, sessions_for_user, db_session
):
    user = await verified_user()
    for _ in range(4):
        await login(user)

    sessions = await sessions_for_user(user["id"])
    now = utcnow()
    sessions[0].expires_at = now - timedelta(minutes=1)
    sessions[1].revoked_at = now - timedelta(days=settings.session_retention_days + 1)
    sessions[2].revoked_at = now - timedelta(minutes=1)
    await db_session.commit()

    removed = await purge_stale_sessions(db_session)

    assert removed == 2
    remaining = {s.id for s in await sessions_for_user(user["id"])}
    assert remaining == {sessions[2].id, sessions[3].id}


async def test_purge_with_nothing_stale_removes_nothing(
    verified_user, login, db_session
):
    user = await verified_user()
    await login(user)

    assert await purge_stale_sessions(db_session) == 0
