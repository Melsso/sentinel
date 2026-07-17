from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinel.database.models import Base
from sentinel.database.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield


app = FastAPI(
    title="Sentinel",
    description="Authentication server",
    lifespan=lifespan,
)
