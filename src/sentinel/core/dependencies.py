from dataclasses import dataclass
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.security import decode_access_token
from sentinel.core.time import utcnow
from sentinel.database.models import Session, User
from sentinel.database.session import get_db


bearer_scheme = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials.",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclass(frozen=True)
class AuthContext:
    user: User
    session: Session


async def get_auth_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    if credentials is None:
        raise _UNAUTHORIZED

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = UUID(payload["sub"])
        session_id = UUID(payload["sid"])
    except (ValueError, KeyError, TypeError):
        raise _UNAUTHORIZED

    session = await db.scalar(
        select(Session).where(Session.id == session_id, Session.user_id == user_id)
    )
    now = utcnow()

    if (
        session is None
        or session.revoked_at is not None
        or session.expires_at < now
        or session.absolute_expires_at < now
    ):
        raise _UNAUTHORIZED

    user = await db.scalar(select(User).where(User.id == user_id))

    if user is None or user.is_deleted:
        raise _UNAUTHORIZED

    return AuthContext(user=user, session=session)


async def get_current_user(
    auth: AuthContext = Depends(get_auth_context),
) -> User:
    return auth.user
