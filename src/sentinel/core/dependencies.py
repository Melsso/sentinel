from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.security import decode_access_token
from sentinel.database.models import User
from sentinel.database.session import get_db


bearer_scheme = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials.",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials is None:
        raise _UNAUTHORIZED

    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError:
        raise _UNAUTHORIZED

    subject = payload.get("sub")

    if subject is None:
        raise _UNAUTHORIZED

    try:
        user_id = UUID(subject)
    except ValueError:
        raise _UNAUTHORIZED

    user = await db.scalar(select(User).where(User.id == user_id))

    if user is None or user.is_deleted:
        raise _UNAUTHORIZED

    return user
