from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.security import (
    password_hasher,
    create_refresh_token,
    hash_token,
)
from sentinel.database.models import AuthProvider, User, Session
from sentinel.schemas.auth import RegisterRequest, LoginRequest
from sentinel.config import settings


class EmailAlreadyExistsError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class InvalidRefreshTokenError(Exception):
    pass


class InvalidSessionError(Exception):
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
        expires_at=datetime.utcnow()
        + timedelta(days=settings.refresh_token_expire_days),
    )

    db.add(session)

    await db.commit()

    return refresh_token


async def refresh_session(db: AsyncSession, refresh_token: str) -> tuple[User, str]:
    token_hash = hash_token(refresh_token)

    session = await db.scalar(
        select(Session).where(Session.refresh_token_hash == token_hash)
    )

    if (
        session is None
        or session.revoked_at is not None
        or session.expires_at < datetime.utcnow()
    ):
        raise InvalidRefreshTokenError()

    user = await db.scalar(select(User).where(User.id == session.user_id))

    if user is None or user.is_deleted:
        raise InvalidRefreshTokenError()

    new_refresh_token = create_refresh_token()

    session.refresh_token_hash = hash_token(new_refresh_token)

    session.expires_at = datetime.utcnow() + timedelta(
        days=settings.refresh_token_expire_days
    )

    await db.commit()

    return user, new_refresh_token


async def logout_user(db: AsyncSession, refresh_token: str) -> None:
    token_hash = hash_token(refresh_token)

    session = await db.scalar(
        select(Session).where(Session.refresh_token_hash == token_hash)
    )

    if session is None:
        raise InvalidSessionError()

    if session.revoked_at is None:
        session.revoked_at = datetime.utcnow()

        await db.commit()
