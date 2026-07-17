import pytest
import pytest_asyncio

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.database.models import Base
from sentinel.database.session import get_db
from sentinel.config import Settings, settings
from sentinel.main import app


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestingSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)


@pytest_asyncio.fixture(scope="session")
async def setup_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(setup_database):
    async with TestingSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession):

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture(scope="session", autouse=True)
def override_settings():
    test_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        redis_url="redis://localhost:6379",
        jwt_secret="test-secret",
        jwt_algorithm="HS256",
        access_token_expire_minutes=5,
        refresh_token_expire_days=1,
    )

    settings.__dict__.update(test_settings.__dict__)

    yield
