# Sentinel

A self-contained authentication service built with FastAPI, Postgres, and Redis. Handles registration, login, session/refresh-token management, email verification, password reset, and account deletion behind a small, typed JSON API.

This is a portfolio project — it's not tied to any particular frontend and doesn't implement OAuth provider callbacks yet (the data model supports them; the routes don't exist).

## Features

- Email/password registration with hashed passwords (Argon2 via `pwdlib`)
- Email verification and password reset emails (pluggable backend: logs to console by default for local dev, or real SMTP delivery to any provider), with a resend-verification endpoint so an expired or missed link isn't a dead end
- Login issuing a short-lived JWT access token + a long-lived, rotating refresh token
- Refresh-token rotation, revocation, and "log out everywhere" (`/logout-all`), plus `/sessions` to see what's active and revoke one specific session instead of all of them
- Account lockout after repeated wrong-password attempts against a single account, on top of (and independent from) the IP/email rate limiting above -- catches slow-rolled guessing from many different IPs that rate limiting alone wouldn't
- Forgot/reset password flow that never reveals whether an email is registered
- Change password / delete account (both require re-entering the current password)
- Per-IP and per-email rate limiting on `/login`, `/register`, and `/forgot-password`
- Structured JSON audit logging of every security-relevant event (logins, failed attempts, password changes, rate-limit trips, ...)
- CORS + basic security headers
- `/health` endpoint that actually checks Postgres and Redis connectivity, not just process liveness

## Tech stack

FastAPI · SQLAlchemy (async) · Postgres · Redis · Argon2 (`pwdlib`) · JWT (`python-jose`) · Poetry · pytest · ruff · mypy

## Quickstart (Docker)

```bash
docker compose up --build
```

This brings up Postgres, Redis, and the app together — the app waits for the other two to report healthy before starting. Once it's up:

```bash
curl http://localhost:8000/health
```

Interactive API docs are at `http://localhost:8000/docs`.

To exercise the whole stack end to end against the real Postgres/Redis (not the SQLite/FakeRedis test suite), run `./scripts/smoke_test.sh` once the containers are up — it registers a user, pulls the verification token from the app's own logs, verifies, logs in, checks `/me` and `/sessions`, rotates a refresh token, confirms the old one is rejected, logs out, triggers rate limiting, and checks the row landed in Postgres. Requires `curl` and `jq`.

By default (`EMAIL_BACKEND=console`), verification/reset emails aren't actually sent anywhere — they're logged as structured JSON (`docker compose logs -f app`, look for `"event": "email_dispatched"`), which includes the link you'd otherwise click. Set `EMAIL_BACKEND=smtp` plus the `SMTP_*` settings in `.env.example` to deliver real email through any provider.

## Running locally without Docker

Requires Python 3.12+, [Poetry](https://python-poetry.org/), and a running Postgres + Redis (`docker compose up postgres redis` is the easiest way to get those two without the app itself).

```bash
poetry install --with dev
cp .env.example .env   # then edit DATABASE_URL/REDIS_URL/JWT_SECRET as needed
poetry run uvicorn sentinel.main:app --reload
```

> Plain `poetry install` only installs the runtime dependencies — this project's dev tools (pytest, ruff, mypy, httpx, ...) live in a separate [PEP 735](https://peps.python.org/pep-0735/) dependency group, so `--with dev` is required to get them.

See `.env.example` for every configurable setting and its default.

## Running tests / linting

```bash
poetry run ruff check .
poetry run mypy .
poetry run pytest
poetry run pip-audit
```

All four also run in CI on every push (`.github/workflows/ci.yml`).

## API overview

All auth routes are under `/auth`.

| Method | Path                     | Auth required | Description                                      |
|--------|--------------------------|----------------|---------------------------------------------------|
| POST   | `/auth/register`         | No             | Create an account                                  |
| POST   | `/auth/login`            | No             | Exchange credentials for an access/refresh token pair |
| POST   | `/auth/refresh`          | No (refresh token) | Rotate a refresh token for a new token pair    |
| POST   | `/auth/logout`           | No (refresh token) | Revoke a single session                        |
| POST   | `/auth/logout-all`       | Yes            | Revoke every active session for the current user   |
| GET    | `/auth/me`               | Yes            | Return the current user                            |
| GET    | `/auth/sessions`         | Yes            | List active sessions (not-revoked, not-expired) for the current user |
| DELETE | `/auth/sessions/{id}`    | Yes            | Revoke one specific session                        |
| POST   | `/auth/verify-email`     | No (email token) | Verify an account's email address                |
| POST   | `/auth/resend-verification-email` | No    | Issue a new verification token (always returns the same response) |
| POST   | `/auth/forgot-password`  | No             | Request a password reset (always returns the same response) |
| POST   | `/auth/reset-password`   | No (reset token) | Set a new password, revokes all sessions        |
| POST   | `/auth/change-password`  | Yes            | Change password, revokes all sessions              |
| DELETE | `/auth/me`               | Yes            | Soft-delete the current account, revokes all sessions |
| GET    | `/health`                | No             | Liveness/readiness check (Postgres + Redis)         |

Full request/response schemas are available at `/docs` once the app is running.

## Project structure

```
src/sentinel/
    core/          # security primitives, rate limiting, logging, redis/http helpers
    database/      # SQLAlchemy models and session setup
    routes/        # FastAPI routers
    schemas/       # pydantic request/response models
    services/      # business logic, independent of the HTTP layer
    config.py      # typed settings, loaded from env vars / .env
    main.py        # app assembly: middleware, routers, startup

tests/             # pytest suite (one file per endpoint/feature area)
```

## Known gaps / not yet implemented

- OAuth provider login (`AuthProvider.GOOGLE` etc. exist in the data model; no callback routes yet)
- Role-based authorization (`UserRole` is stored but nothing currently checks it)

## License

MIT.