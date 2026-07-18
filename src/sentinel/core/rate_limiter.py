import logging

from fastapi import HTTPException, Request, status

from sentinel.config import settings
from sentinel.core.http import get_client_ip
from sentinel.core.logging import log_auth_event
from sentinel.core.redis import get_redis


def rate_limit(scope: str, limit_attr: str, window_attr: str, by_email: bool = False):

    async def dependency(request: Request) -> None:
        limit = getattr(settings, limit_attr)
        window_seconds = getattr(settings, window_attr)

        redis_client = get_redis()
        keys = [f"ratelimit:{scope}:ip:{get_client_ip(request)}"]

        if by_email:
            try:
                body = await request.json()
            except ValueError:
                body = {}

            email = body.get("email") if isinstance(body, dict) else None

            if email:
                keys.append(f"ratelimit:{scope}:email:{str(email).strip().lower()}")

        for key in keys:
            count = await redis_client.incr(key)

            if count == 1:
                await redis_client.expire(key, window_seconds)

            if count > limit:
                log_auth_event(
                    "rate_limit_exceeded",
                    request,
                    level=logging.WARNING,
                    scope=scope,
                    limit_key=key,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again later.",
                    headers={"Retry-After": str(window_seconds)},
                )

    return dependency
