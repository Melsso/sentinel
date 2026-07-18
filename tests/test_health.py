import pytest


pytestmark = pytest.mark.asyncio


async def test_health_success(client):
    response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    assert data["redis"] == "ok"


async def test_health_reports_redis_outage(client, redis, monkeypatch):
    async def broken_ping():
        raise ConnectionError("redis is down")

    monkeypatch.setattr(redis, "ping", broken_ping)

    response = await client.get("/health")

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "degraded"
    assert data["redis"] == "unreachable"
    assert data["database"] == "ok"
