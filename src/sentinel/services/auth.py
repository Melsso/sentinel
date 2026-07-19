from datetime import timedelta
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.security import (
    password_hasher,
    create_refresh_token,
    hash_token,
    create_verification_token,
)
from sentinel.core.redis import set_value, get_value, delete_value
from sentinel.core.time import utcnow
from sentinel.core.email import send_email
from sentinel.core.email_templates import verification_email, password_reset_email
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


class InvalidVerificationTokenError(Exception):
    pass


class InvalidResetTokenError(Exception):
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

    await create_email_verification_token(user)

    return user


async def authenticate_user(db: AsyncSession, data: LoginRequest) -> User:
    email = data.email.strip().lower()

    user = await db.scalar(select(User).where(User.email == email))

    if (
        user is None
        or user.password_hash is None
        or not user.is_verified
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
        expires_at=utcnow() + timedelta(days=settings.refresh_token_expire_days),
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
        or session.expires_at < utcnow()
    ):
        raise InvalidRefreshTokenError()

    user = await db.scalar(select(User).where(User.id == session.user_id))

    if user is None or user.is_deleted:
        raise InvalidRefreshTokenError()

    new_refresh_token = create_refresh_token()

    session.refresh_token_hash = hash_token(new_refresh_token)

    session.expires_at = utcnow() + timedelta(days=settings.refresh_token_expire_days)

    await db.commit()

    return user, new_refresh_token


async def logout_user(db: AsyncSession, refresh_token: str) -> UUID:
    token_hash = hash_token(refresh_token)

    session = await db.scalar(
        select(Session).where(Session.refresh_token_hash == token_hash)
    )

    if session is None:
        raise InvalidSessionError()

    if session.revoked_at is None:
        session.revoked_at = utcnow()

        await db.commit()

    return session.user_id


async def create_email_verification_token(user: User) -> str:
    token = create_verification_token()

    await set_value(
        f"email_verify:{token}",
        str(user.id),
        settings.email_verification_expire_minutes * 60,
    )

    subject, body = verification_email(token)
    await send_email(user.email, subject, body)

    return token


async def verify_email(db: AsyncSession, token: str) -> User:
    user_id = await get_value(f"email_verify:{token}")

    if user_id is None:
        raise InvalidVerificationTokenError()

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise InvalidVerificationTokenError()

    user = await db.scalar(select(User).where(User.id == user_uuid))

    if user is None or user.is_deleted:
        raise InvalidVerificationTokenError()

    user.is_verified = True

    await delete_value(f"email_verify:{token}")

    await db.commit()
    await db.refresh(user)

    return user


async def resend_verification_email(db: AsyncSession, email: str) -> bool:
    normalized_email = email.strip().lower()

    user = await db.scalar(select(User).where(User.email == normalized_email))

    if (
        user is None
        or user.is_deleted
        or user.is_verified
        or user.provider != AuthProvider.LOCAL
    ):
        return False

    await create_email_verification_token(user)

    return True


async def list_active_sessions(db: AsyncSession, user: User) -> list[Session]:
    result = await db.scalars(
        select(Session)
        .where(
            Session.user_id == user.id,
            Session.revoked_at.is_(None),
            Session.expires_at > utcnow(),
        )
        .order_by(Session.created_at.desc())
    )

    return list(result)


async def revoke_all_sessions(db: AsyncSession, user: User, commit: bool = True) -> int:
    result = await db.scalars(
        select(Session).where(
            Session.user_id == user.id,
            Session.revoked_at.is_(None),
        )
    )
    sessions = list(result)
    now = utcnow()

    for session in sessions:
        session.revoked_at = now

    if commit:
        await db.commit()

    return len(sessions)


async def create_password_reset_token(user: User) -> str:
    token = create_verification_token()

    await set_value(
        f"password_reset:{token}",
        str(user.id),
        settings.password_reset_expire_minutes * 60,
    )

    subject, body = password_reset_email(token)
    await send_email(user.email, subject, body)

    return token


async def request_password_reset(db: AsyncSession, email: str) -> bool:
    normalized_email = email.strip().lower()

    user = await db.scalar(select(User).where(User.email == normalized_email))

    if user is None or user.is_deleted or user.provider != AuthProvider.LOCAL:
        return False

    await create_password_reset_token(user)

    return True


async def reset_password(db: AsyncSession, token: str, new_password: str) -> UUID:
    user_id = await get_value(f"password_reset:{token}")

    if user_id is None:
        raise InvalidResetTokenError()

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise InvalidResetTokenError()

    user = await db.scalar(select(User).where(User.id == user_uuid))

    if user is None or user.is_deleted:
        raise InvalidResetTokenError()

    user.password_hash = password_hasher.hash(new_password)

    await delete_value(f"password_reset:{token}")
    await revoke_all_sessions(db, user, commit=False)

    await db.commit()

    return user.id


async def change_password(
    db: AsyncSession, user: User, current_password: str, new_password: str
) -> None:
    if user.password_hash is None or not password_hasher.verify(
        current_password, user.password_hash
    ):
        raise InvalidCredentialsError()

    user.password_hash = password_hasher.hash(new_password)

    await revoke_all_sessions(db, user, commit=False)

    await db.commit()


async def delete_account(db: AsyncSession, user: User, password: str) -> None:
    if user.provider == AuthProvider.LOCAL:
        if user.password_hash is None or not password_hasher.verify(
            password, user.password_hash
        ):
            raise InvalidCredentialsError()

    user.is_deleted = True

    await revoke_all_sessions(db, user, commit=False)

    await db.commit()
