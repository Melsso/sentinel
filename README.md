# Sentinel

A self-contained authentication service built with FastAPI, Postgres, and Redis. Handles registration, login, session/refresh-token management, email verification, password reset, and account deletion behind a small, typed JSON API.

This is a portfolio project — it's not tied to any particular frontend and doesn't implement OAuth provider callbacks yet (the data model supports them; the routes don't exist).

## Features

- Email/password registration with hashed passwords (Argon2 via `pwdlib`)
- Email verification (Redis-backed, one-time-use tokens)
- Login issuing a short-lived JWT access token + a long-lived, rotating refresh token
- Refresh-token rotation, revocation, and "log out everywhere" (`/logout-all`)
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
```

All three also run in CI on every push (`.github/workflows/ci.yml`).

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
| POST   | `/auth/verify-email`     | No (email token) | Verify an account's email address                |
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
- Actual email delivery — verification/reset tokens are generated and stored in Redis, but nothing sends them anywhere yet (check Redis directly, or add an email provider integration)
- Role-based authorization (`UserRole` is stored but nothing currently checks it)
- Database migrations (schema is created via `Base.metadata.create_all` at startup)