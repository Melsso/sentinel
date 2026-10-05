import asyncio
import os

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

import sentinel.core.redis as redis_module
from sentinel.core.redis import consume_value, incr_with_ttl, set_value

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("INTEGRATION_REDIS_URL"),
        reason="set INTEGRATION_REDIS_URL to a throwaway Redis DB to run",
    ),
]


@pytest_asyncio.fixture
async def real_redis(monkeypatch):
    client = aioredis.from_url(
        os.environ["INTEGRATION_REDIS_URL"], decode_responses=True
    )
    await client.flushdb()
    monkeypatch.setattr(redis_module, "_client", client)

    yield client

    await client.flushdb()
    await client.aclose()


async def test_one_time_token_is_consumed_by_exactly_one_caller(real_redis):
    await set_value("email_verify:abc", "user-1", 60)

    results = await asyncio.gather(
        *(consume_value("email_verify:abc") for _ in range(25))
    )

    assert [r for r in results if r is not None] == ["user-1"]
    assert await real_redis.exists("email_verify:abc") == 0


async def test_incr_with_ttl_counts_and_always_sets_a_ttl(real_redis):
    counts = [await incr_with_ttl("ratelimit:test", 30) for _ in range(3)]

    assert counts == [1, 2, 3]
    assert 0 < await real_redis.ttl("ratelimit:test") <= 30


async def test_concurrent_incr_with_ttl_never_leaves_a_key_without_ttl(real_redis):
    await asyncio.gather(*(incr_with_ttl("ratelimit:race", 30) for _ in range(50)))

    assert int(await real_redis.get("ratelimit:race")) == 50
    assert await real_redis.ttl("ratelimit:race") > 0
