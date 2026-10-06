from datetime import datetime, timedelta
from uuid import UUID

from fastapi import BackgroundTasks
from sqlalchemy import delete, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.config import settings
from sentinel.core.email import send_email
from sentinel.core.email_templates import (
    account_exists_email,
    password_reset_email,
    verification_email,
)
from sentinel.core.redis import consume_value, get_redis, incr_with_ttl, set_value
from sentinel.core.security import (
    DUMMY_PASSWORD_HASH,
    create_refresh_token,
    create_verification_token,
    hash_password,
    hash_token,
    verify_password,
)
from sentinel.core.time import utcnow
from sentinel.database.models import Session, UsedRefreshToken, User
from sentinel.schemas.auth import LoginRequest, RegisterRequest


class InvalidCredentialsError(Exception):
    pass


class AccountLockedError(Exception):
    pass


class InvalidRefreshTokenError(Exception):
    pass


class RefreshTokenReuseError(InvalidRefreshTokenError):
    def __init__(self, user_id: UUID, session_id: UUID) -> None:
        super().__init__("refresh token reuse detected")
        self.user_id = user_id
        self.session_id = session_id


class InvalidSessionError(Exception):
    pass


class InvalidVerificationTokenError(Exception):
    pass


class InvalidResetTokenError(Exception):
    pass


async def register_user(
    db: AsyncSession, data: RegisterRequest, background: BackgroundTasks
) -> User | None:
    email = data.email.strip().lower()
    password_hash = await hash_password(data.password)

    existing = await db.scalar(select(User).where(User.email == email))

    if existing is None:
        user = User(email=email, password_hash=password_hash, is_deleted=False)
        db.add(user)

        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            existing = await db.scalar(select(User).where(User.email == email))

            if existing is None:
                raise
        else:
            await db.refresh(user)
            await create_email_verification_token(user, background)
            return user

    await _notify_existing_account(existing, background)

    return None


async def _notify_existing_account(user: User, background: BackgroundTasks) -> None:
    if not user.is_verified and not user.is_deleted:
        await create_email_verification_token(user, background)
        return

    subject, body = account_exists_email()
    background.add_task(send_email, user.email, subject, body)


async def _clear_all_login_failures(email: str) -> None:
    redis_client = get_redis()
    escaped = "".join(f"\\{c}" if c in "\\*?[]" else c for c in email)

    for prefix in (_FAILURE_KEY_PREFIX, _LOCKOUT_KEY_PREFIX):
        async for key in redis_client.scan_iter(match=f"{prefix}:{escaped}:*"):
            await redis_client.delete(key)


_LOCKOUT_KEY_PREFIX = "login_lockout"
_FAILURE_KEY_PREFIX = "login_failures"


def _lockout_key(email: str, client_ip: str) -> str:
    return f"{_LOCKOUT_KEY_PREFIX}:{email}:{client_ip}"


def _failure_key(email: str, client_ip: str) -> str:
    return f"{_FAILURE_KEY_PREFIX}:{email}:{client_ip}"


async def _is_account_locked(email: str, client_ip: str) -> bool:
    return bool(await get_redis().exists(_lockout_key(email, client_ip)))


async def _register_failed_login(email: str, client_ip: str) -> None:
    redis_client = get_redis()
    failure_key = _failure_key(email, client_ip)

    count = await incr_with_ttl(failure_key, settings.login_lockout_duration_seconds)

    if count >= settings.login_lockout_threshold:
        await redis_client.set(
            _lockout_key(email, client_ip),
            "1",
            ex=settings.login_lockout_duration_seconds,
        )
        await redis_client.delete(failure_key)


async def _clear_login_failures(email: str, client_ip: str) -> None:
    redis_client = get_redis()

    await redis_client.delete(_failure_key(email, client_ip))
    await redis_client.delete(_lockout_key(email, client_ip))


async def authenticate_user(
    db: AsyncSession, data: LoginRequest, client_ip: str
) -> User:
    email = data.email.strip().lower()

    locked = await _is_account_locked(email, client_ip)
    user = await db.scalar(select(User).where(User.email == email))

    stored_hash = (
        user.password_hash
        if user is not None and user.password_hash is not None
        else DUMMY_PASSWORD_HASH
    )
    password_ok = await verify_password(data.password, stored_hash)

    if locked:
        raise AccountLockedError()

    if (
        user is None
        or user.password_hash is None
        or not user.is_verified
        or user.is_deleted
    ):
        raise InvalidCredentialsError()

    if not password_ok:
        await _register_failed_login(email, client_ip)
        raise InvalidCredentialsError()

    await _clear_login_failures(email, client_ip)

    return user


def _session_expiry(now: datetime, absolute_expires_at: datetime) -> datetime:
    return min(
        now + timedelta(days=settings.refresh_token_expire_days),
        absolute_expires_at,
    )


async def create_session(
    db: AsyncSession,
    user: User,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[Session, str]:
    refresh_token = create_refresh_token()
    now = utcnow()
    absolute_expires_at = now + timedelta(days=settings.session_absolute_lifetime_days)

    session = Session(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        ip_address=ip_address,
        user_agent=user_agent[:512] if user_agent else None,
        expires_at=_session_expiry(now, absolute_expires_at),
        absolute_expires_at=absolute_expires_at,
    )

    db.add(session)

    await db.commit()

    return session, refresh_token


async def _detect_reuse(db: AsyncSession, token_hash: str) -> None:
    used = await db.scalar(
        select(UsedRefreshToken).where(UsedRefreshToken.token_hash == token_hash)
    )

    if used is None:
        return

    session = await db.get(Session, used.session_id)

    if session is None:
        return

    if session.revoked_at is None:
        session.revoked_at = utcnow()
        await db.commit()

    raise RefreshTokenReuseError(session.user_id, session.id)


async def refresh_session(
    db: AsyncSession, refresh_token: str
) -> tuple[User, Session, str]:
    token_hash = hash_token(refresh_token)
    now = utcnow()

    session = await db.scalar(
        select(Session).where(Session.refresh_token_hash == token_hash)
    )

    if session is None:
        await _detect_reuse(db, token_hash)
        raise InvalidRefreshTokenError()

    if (
        session.revoked_at is not None
        or session.expires_at < now
        or session.absolute_expires_at < now
    ):
        raise InvalidRefreshTokenError()

    user = await db.scalar(select(User).where(User.id == session.user_id))

    if user is None or user.is_deleted:
        raise InvalidRefreshTokenError()

    new_refresh_token = create_refresh_token()

    result = await db.execute(
        update(Session)
        .where(
            Session.id == session.id,
            Session.refresh_token_hash == token_hash,
            Session.revoked_at.is_(None),
        )
        .values(
            refresh_token_hash=hash_token(new_refresh_token),
            expires_at=_session_expiry(now, session.absolute_expires_at),
        )
        .returning(Session.id)
        .execution_options(synchronize_session=False)
    )

    if result.scalar_one_or_none() is None:
        await db.rollback()
        await _detect_reuse(db, token_hash)
        raise InvalidRefreshTokenError()

    db.add(UsedRefreshToken(token_hash=token_hash, session_id=session.id, used_at=now))

    await db.commit()
    await db.refresh(session)

    return user, session, new_refresh_token


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


async def create_email_verification_token(
    user: User, background: BackgroundTasks
) -> str:
    token = create_verification_token()

    await set_value(
        f"email_verify:{hash_token(token)}",
        str(user.id),
        settings.email_verification_expire_minutes * 60,
    )

    subject, body = verification_email(token)
    background.add_task(send_email, user.email, subject, body)

    return token


async def verify_email(db: AsyncSession, token: str) -> User:
    user_id = await consume_value(f"email_verify:{hash_token(token)}")

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

    await db.commit()
    await db.refresh(user)

    return user


async def resend_verification_email(
    db: AsyncSession, email: str, background: BackgroundTasks
) -> bool:
    normalized_email = email.strip().lower()

    user = await db.scalar(select(User).where(User.email == normalized_email))

    if user is None or user.is_deleted or user.is_verified:
        return False

    await create_email_verification_token(user, background)

    return True


async def list_active_sessions(db: AsyncSession, user: User) -> list[Session]:
    now = utcnow()

    result = await db.scalars(
        select(Session)
        .where(
            Session.user_id == user.id,
            Session.revoked_at.is_(None),
            Session.expires_at > now,
            Session.absolute_expires_at > now,
        )
        .order_by(Session.created_at.desc())
    )

    return list(result)


async def revoke_session(db: AsyncSession, user: User, session_id: UUID) -> bool:
    session = await db.scalar(
        select(Session).where(Session.id == session_id, Session.user_id == user.id)
    )

    if session is None:
        return False

    if session.revoked_at is None:
        session.revoked_at = utcnow()
        await db.commit()

    return True


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


async def create_password_reset_token(user: User, background: BackgroundTasks) -> str:
    token = create_verification_token()

    await set_value(
        f"password_reset:{hash_token(token)}",
        str(user.id),
        settings.password_reset_expire_minutes * 60,
    )

    subject, body = password_reset_email(token)
    background.add_task(send_email, user.email, subject, body)

    return token


async def request_password_reset(
    db: AsyncSession, email: str, background: BackgroundTasks
) -> bool:
    normalized_email = email.strip().lower()

    user = await db.scalar(select(User).where(User.email == normalized_email))

    if user is None or user.is_deleted:
        return False

    await create_password_reset_token(user, background)

    return True


async def reset_password(db: AsyncSession, token: str, new_password: str) -> UUID:
    user_id = await consume_value(f"password_reset:{hash_token(token)}")

    if user_id is None:
        raise InvalidResetTokenError()

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise InvalidResetTokenError()

    user = await db.scalar(select(User).where(User.id == user_uuid))

    if user is None or user.is_deleted:
        raise InvalidResetTokenError()

    user.password_hash = await hash_password(new_password)

    await revoke_all_sessions(db, user, commit=False)

    await db.commit()

    await _clear_all_login_failures(user.email)

    return user.id


async def change_password(
    db: AsyncSession, user: User, current_password: str, new_password: str
) -> None:
    if user.password_hash is None or not await verify_password(
        current_password, user.password_hash
    ):
        raise InvalidCredentialsError()

    user.password_hash = await hash_password(new_password)

    await revoke_all_sessions(db, user, commit=False)

    await db.commit()


async def delete_account(db: AsyncSession, user: User, password: str) -> None:
    if user.password_hash is None or not await verify_password(
        password, user.password_hash
    ):
        raise InvalidCredentialsError()

    session_ids = select(Session.id).where(Session.user_id == user.id)
    await db.execute(
        delete(UsedRefreshToken).where(UsedRefreshToken.session_id.in_(session_ids))
    )
    await db.execute(delete(Session).where(Session.user_id == user.id))

    user.email = f"deleted-{user.id.hex}@deleted.invalid"
    user.password_hash = None
    user.is_verified = False
    user.is_deleted = True

    await db.commit()


async def purge_stale_sessions(db: AsyncSession) -> int:
    now = utcnow()
    revoked_cutoff = now - timedelta(days=settings.session_retention_days)

    stale_ids = select(Session.id).where(
        or_(
            Session.expires_at < now,
            Session.absolute_expires_at < now,
            Session.revoked_at < revoked_cutoff,
        )
    )

    await db.execute(
        delete(UsedRefreshToken).where(UsedRefreshToken.session_id.in_(stale_ids))
    )
    result = await db.execute(
        delete(Session).where(Session.id.in_(stale_ids)).returning(Session.id)
    )
    removed = len(result.all())

    await db.commit()

    return removed
