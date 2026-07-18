from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.redis import get_redis
from sentinel.database.session import get_db

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health(response: Response, db: AsyncSession = Depends(get_db)):
    checks = {"database": "ok", "redis": "ok"}

    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        checks["database"] = "unreachable"

    try:
        await get_redis().ping()
    except Exception:
        checks["redis"] = "unreachable"

    healthy = all(value == "ok" for value in checks.values())
    response.status_code = (
        status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return {"status": "ok" if healthy else "degraded", **checks}
