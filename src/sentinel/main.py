import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from sentinel.config import settings
from sentinel.core.email import get_email_sender
from sentinel.core.logging import configure_logging
from sentinel.database.models import Base
from sentinel.database.session import SessionLocal, engine

from sentinel.routes.auth import router as auth_router
from sentinel.routes.health import router as health_router
from sentinel.services.auth import purge_stale_sessions

configure_logging(settings.log_level)

maintenance_logger = logging.getLogger("sentinel.maintenance")


async def _purge_sessions_forever() -> None:
    while True:
        try:
            async with SessionLocal() as db:
                removed = await purge_stale_sessions(db)

            if removed:
                maintenance_logger.info(
                    "sessions_purged",
                    extra={"event": "sessions_purged", "count": removed},
                )
        except Exception:
            maintenance_logger.exception(
                "session_purge_failed", extra={"event": "session_purge_failed"}
            )

        await asyncio.sleep(settings.session_purge_interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_email_sender()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    purge_task = asyncio.create_task(_purge_sessions_forever())

    try:
        yield
    finally:
        purge_task.cancel()
        with suppress(asyncio.CancelledError):
            await purge_task


app = FastAPI(
    title="Sentinel",
    description="Authentication server",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains"
    )

    return response


app.include_router(auth_router)
app.include_router(health_router)
