import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pwdlib import PasswordHash

from sentinel.config import settings


password_hasher = PasswordHash.recommended()

DUMMY_PASSWORD_HASH = password_hasher.hash("sentinel-timing-equalizer")
ACCESS_TOKEN_TYPE = "access"
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "sid", "typ", "iss", "aud"]


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(password_hasher.hash, password)


async def verify_password(password: str, hashed: str) -> bool:
    return await asyncio.to_thread(password_hasher.verify, password, hashed)


def create_access_token(
    subject: str, session_id: str, expires_delta: timedelta | None = None
) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.access_token_expire_minutes)
    )

    payload = {
        "sub": subject,
        "sid": session_id,
        "typ": ACCESS_TOKEN_TYPE,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token() -> str:
    return secrets.token_urlsafe(64)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise ValueError("Invalid token") from exc

    if payload.get("typ") != ACCESS_TOKEN_TYPE:
        raise ValueError("Invalid token type")

    return payload


def create_verification_token() -> str:
    return secrets.token_urlsafe(32)
