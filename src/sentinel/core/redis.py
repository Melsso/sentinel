import redis.asyncio as redis
from typing import cast

from sentinel.config import settings


_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client

    if _client is None:
        _client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )

    return _client


async def set_value(key: str, value: str, expire_seconds: int):
    await get_redis().set(
        key,
        value,
        ex=expire_seconds,
    )


async def get_value(key: str) -> str | None:
    value = await get_redis().get(key)
    return cast("str | None", value)


async def delete_value(key: str):
    await get_redis().delete(key)
