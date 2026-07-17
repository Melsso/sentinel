from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.security import (
    password_hasher,
    create_refresh_token,
    hash_token,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from sentinel.database.models import AuthProvider, User, Session
from sentinel.schemas.auth import RegisterRequest, LoginRequest


class EmailAlreadyExistsError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


async def register_user(db: AsyncSession, data: RegisterRequest) -> User:
    email = data.email.strip().lower()

    existing = await db.scalar(select(User).where(User.email == email))

    if existing is not None:
        raise EmailAlreadyExistsError()

    user = User(
        email=email,
        password_hash=password_hasher.hash(data.password),
        provider=AuthProvider.LOCAL,
        date_of_birth=data.date_of_birth,
        is_deleted=False,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def authenticate_user(db: AsyncSession, data: LoginRequest) -> User:
    email = data.email.strip().lower()

    user = await db.scalar(select(User).where(User.email == email))

    if (
        user is None
        or user.password_hash is None
        or user.is_deleted
        or not password_hasher.verify(data.password, user.password_hash)
    ):
        raise InvalidCredentialsError()

    return user


async def create_session(db: AsyncSession, user: User) -> str:
    refresh_token = create_refresh_token()

    session = Session(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    db.add(session)

    await db.commit()

    return refresh_token
