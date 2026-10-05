import redis.asyncio as redis
from typing import cast

from sentinel.config import settings


_client: redis.Redis | None = None

_INCR_WITH_TTL_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


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


async def consume_value(key: str) -> str | None:
    """Atomically read and delete a key (GETDEL): one-time tokens."""
    value = await get_redis().getdel(key)
    return cast("str | None", value)


async def incr_with_ttl(key: str, ttl_seconds: int) -> int:
    count = await get_redis().eval(_INCR_WITH_TTL_SCRIPT, 1, key, ttl_seconds)
    return int(count)
