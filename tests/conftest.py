import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.config import settings
from sentinel.core.security import hash_token
from sentinel.database.models import AuthProvider, Base, Session, User
from sentinel.database.session import get_db
from sentinel.main import app

settings.database_url = "sqlite+aiosqlite:///:memory:"
settings.redis_url = "redis://test"
settings.jwt_secret = "test-secret"
settings.jwt_algorithm = "HS256"
settings.access_token_expire_minutes = 5
settings.refresh_token_expire_days = 1
settings.email_verification_expire_minutes = 30
settings.password_reset_expire_minutes = 30

settings.login_rate_limit = 5
settings.login_rate_limit_window_seconds = 60
settings.register_rate_limit = 20
settings.register_rate_limit_window_seconds = 60
settings.forgot_password_rate_limit = 5
settings.forgot_password_rate_limit_window_seconds = 60

engine = create_async_engine(settings.database_url, future=True)
TestingSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)

DEFAULT_PASSWORD = "Password123!"


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}@example.com"


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


@pytest_asyncio.fixture(scope="session", autouse=True)
async def database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(database):
    async with TestingSessionLocal() as session:
        yield session

        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(table.delete())

        await session.commit()


class FakeRedis:
    def __init__(self):
        self.storage = {}

    async def set(self, key, value, ex=None):
        self.storage[key] = value

    async def get(self, key):
        return self.storage.get(key)

    async def delete(self, key):
        self.storage.pop(key, None)

    async def keys(self, pattern="*"):
        return list(self.storage.keys())

    async def exists(self, key):
        return key in self.storage

    async def flushall(self):
        self.storage.clear()

    async def ping(self):
        return True

    async def incr(self, key):
        current = int(self.storage.get(key, "0")) + 1
        self.storage[key] = str(current)
        return current

    async def expire(self, key, seconds):
        return True


@pytest.fixture
def redis(monkeypatch):
    import sentinel.core.redis as redis_module

    fake = FakeRedis()

    monkeypatch.setattr(redis_module, "_client", fake)

    return fake


@pytest_asyncio.fixture
async def client(db_session: AsyncSession, redis):

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def register(client):

    async def _register(
        email: str | None = None, password: str = DEFAULT_PASSWORD, **extra
    ):
        email = email or unique_email()
        payload = {"email": email, "password": password, **extra}
        response = await client.post("/auth/register", json=payload)
        return email, password, response

    return _register


@pytest_asyncio.fixture
async def find_verification_token(redis):

    def _find(user_id) -> str | None:
        target = str(user_id)
        for key, value in redis.storage.items():
            if key.startswith("email_verify:") and value == target:
                return key.removeprefix("email_verify:")
        return None

    return _find


@pytest_asyncio.fixture
async def verified_user(client, register, find_verification_token):

    async def _make(email: str | None = None, password: str = DEFAULT_PASSWORD) -> dict:
        email, password, response = await register(email=email, password=password)
        assert response.status_code == 201, response.text
        user_id = response.json()["id"]

        token = find_verification_token(user_id)
        assert token is not None, "verification token was not stored in redis"

        verify_response = await client.post("/auth/verify-email", json={"token": token})
        assert verify_response.status_code == 200, verify_response.text

        return {"email": email, "password": password, "id": user_id}

    return _make


@pytest_asyncio.fixture
async def make_db_user(db_session):

    async def _make(**overrides) -> User:
        defaults = dict(
            email=unique_email(),
            password_hash=None,
            provider=AuthProvider.LOCAL,
            is_verified=True,
            is_deleted=False,
        )
        defaults.update(overrides)
        user = User(**defaults)
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _make


@pytest_asyncio.fixture
async def get_user(db_session):

    async def _get(user_id) -> User | None:
        uid = uuid.UUID(str(user_id))
        return await db_session.scalar(select(User).where(User.id == uid))

    return _get


@pytest_asyncio.fixture
async def update_user(get_user, db_session):

    async def _update(user_id, **fields) -> User:
        user = await get_user(user_id)
        assert user is not None
        for key, value in fields.items():
            setattr(user, key, value)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _update


@pytest_asyncio.fixture
async def get_session_for_token(db_session):

    async def _get(refresh_token: str) -> Session | None:
        return await db_session.scalar(
            select(Session).where(
                Session.refresh_token_hash == hash_token(refresh_token)
            )
        )

    return _get


@pytest_asyncio.fixture
async def sessions_for_user(db_session):

    async def _list(user_id) -> list[Session]:
        uid = uuid.UUID(str(user_id))
        result = await db_session.scalars(select(Session).where(Session.user_id == uid))
        return list(result)

    return _list


@pytest_asyncio.fixture
async def login(client):

    async def _login(user: dict) -> dict:
        response = await client.post(
            "/auth/login",
            json={"email": user["email"], "password": user["password"]},
        )
        assert response.status_code == 200, response.text
        return response.json()

    return _login


@pytest_asyncio.fixture
async def auth_headers(login):

    async def _headers(user: dict) -> dict:
        tokens = await login(user)
        return {"Authorization": f"Bearer {tokens['access_token']}"}

    return _headers


@pytest_asyncio.fixture
async def find_password_reset_token(redis):

    def _find(user_id) -> str | None:
        target = str(user_id)
        for key, value in redis.storage.items():
            if key.startswith("password_reset:") and value == target:
                return key.removeprefix("password_reset:")
        return None

    return _find
