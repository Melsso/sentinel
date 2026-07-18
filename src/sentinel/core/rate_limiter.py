from fastapi import HTTPException, Request, status

from sentinel.config import settings
from sentinel.core.redis import get_redis


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        return forwarded.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


def rate_limit(scope: str, limit_attr: str, window_attr: str, by_email: bool = False):

    async def dependency(request: Request) -> None:
        limit = getattr(settings, limit_attr)
        window_seconds = getattr(settings, window_attr)

        redis_client = get_redis()
        keys = [f"ratelimit:{scope}:ip:{_client_ip(request)}"]

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
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again later.",
                    headers={"Retry-After": str(window_seconds)},
                )

    return dependency
