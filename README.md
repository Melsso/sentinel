# Sentinel

A self-contained authentication service built with FastAPI, Postgres, and Redis. It handles registration, login, session and refresh-token management, email verification, password reset, and account deletion behind a small, typed JSON API.

Sentinel is a **service**, not a library: it reads its configuration from environment variables when imported and is meant to be run and called over HTTP. This is a portfolio project; it is not tied to any frontend.

## Features

**Accounts**
- Email/password registration with Argon2 hashing (`pwdlib`). Emails are normalised to lowercase.
- Email verification via a single-use, expiring link, plus a resend endpoint. Login requires a verified email.
- Forgot/reset password flow via a single-use, expiring link. Resetting revokes all sessions and clears the account's login lockout counters.
- Change password (requires the current password; revokes all sessions).
- Delete account (requires the password): the user row is anonymised (email replaced with a placeholder, password hash removed), all of the user's sessions are deleted, and the original email can be registered again.

**Tokens and sessions**
- Login returns a short-lived JWT access token (HS256; `sub`, `sid`, `typ`, `iss`, `aud`, `iat`, `exp` claims) and an opaque, long-lived refresh token. Refresh tokens are stored only as SHA-256 hashes.
- Every access token is tied to a session and is rejected as soon as that session is revoked (logout, logout-all, revoking one session, password change or reset, account deletion).
- Refresh-token rotation is atomic, so concurrent refreshes with the same token cannot both succeed.
- Refresh-token reuse detection: presenting an already-rotated refresh token revokes the whole session.
- Sessions expire after `REFRESH_TOKEN_EXPIRE_DAYS` of inactivity (sliding) and never live longer than `SESSION_ABSOLUTE_LIFETIME_DAYS`.
- `/auth/sessions` lists active sessions with the IP and user agent recorded at login and marks the current one; individual sessions can be revoked, or all of them via `/auth/logout-all`.
- A background task purges expired sessions, and sessions revoked more than `SESSION_RETENTION_DAYS` ago.

**Abuse protection**
- Rate limiting on `/auth/login` (per IP and per email), `/auth/register` (per IP), `/auth/forgot-password` and `/auth/resend-verification-email` (per IP and per email). Counters use a Lua script so a counter and its TTL are set atomically.
- Account lockout after `LOGIN_LOCKOUT_THRESHOLD` wrong passwords, scoped to the (email, client IP) pair so another party cannot lock the owner out from a different IP. A locked login returns the same response as wrong credentials.
- No account enumeration through responses: `/register`, `/forgot-password` and `/resend-verification-email` return the same response whether or not the email exists, and login returns one generic error. Password hashing is performed on every login and registration path to keep timing similar.
- `X-Forwarded-For` is only trusted from proxies listed in `TRUSTED_PROXIES` (empty by default, meaning ignored).

**Operations**
- Verification and reset emails are sent from background tasks with retry and backoff, over SMTP (any provider) or a console backend for local development. The console backend logs full messages including links, and is refused unless `ALLOW_CONSOLE_EMAIL=true`.
- Startup validation: refuses a `JWT_SECRET` shorter than 32 characters or a known placeholder, an unusable email backend, or an invalid `TRUSTED_PROXIES`.
- Structured JSON audit logging of security-relevant events. Email addresses in audit logs are hashed unless `LOG_PII=true`; client IPs are always logged.
- CORS and basic security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Strict-Transport-Security`).
- `/health` checks Postgres and Redis connectivity, not just process liveness.

## Tech stack

FastAPI · SQLAlchemy (async) · Postgres · Redis · Argon2 (`pwdlib`) · PyJWT · Poetry · pytest · ruff · mypy

## Quickstart (Docker)

```bash
cp .env.example .env    # then set JWT_SECRET (at least 32 characters)
docker compose up --build
```

`JWT_SECRET` is required: Compose refuses to start without it. Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

This brings up Postgres, Redis, and the app together; the app waits for the other two to report healthy. Once it's up:

```bash
curl http://localhost:8000/health
```

Interactive API docs are at `http://localhost:8000/docs`.

The dev stack uses `EMAIL_BACKEND=console` (with `ALLOW_CONSOLE_EMAIL=true`), so verification and reset emails are logged instead of sent: `docker compose logs -f app`, look for `"event": "email_dispatched"`. Set `EMAIL_BACKEND=smtp` and the `SMTP_*` settings to deliver real mail.

To exercise the stack end to end against real Postgres and Redis, run `./scripts/smoke_test.sh` once the containers are up. It registers a user, pulls the verification token from the app's logs, verifies, logs in, checks `/me` and `/sessions`, rotates a refresh token, checks that replaying the old one revokes the session, fires concurrent refreshes and checks exactly one succeeds, triggers rate limiting, and checks the row landed in Postgres. Requires `curl` and `jq`.

## Running locally without Docker

Requires Python 3.11 - 3.13, [Poetry](https://python-poetry.org/), and a running Postgres and Redis (`docker compose up postgres redis` is the easiest way to get those two).

```bash
poetry install --with dev
cp .env.example .env    # then set DATABASE_URL, REDIS_URL, JWT_SECRET, and ALLOW_CONSOLE_EMAIL=true or SMTP settings
poetry run uvicorn sentinel.main:app --reload
```

> Plain `poetry install` only installs runtime dependencies. Dev tools (pytest, ruff, mypy, httpx, ...) live in a separate [PEP 735](https://peps.python.org/pep-0735/) dependency group, so `--with dev` is required.

See `.env.example` for every setting and its default.

## Running tests / linting

```bash
poetry run ruff check .
poetry run mypy .
poetry run pytest
poetry run pip-audit
```

The test suite uses SQLite and an in-memory fake Redis. `tests/test_redis_integration.py` runs against a real Redis when `INTEGRATION_REDIS_URL` is set (it **flushes** that Redis database, so point it at a throwaway one). In CI, the checks above run on Python 3.11 - 3.13 with a Redis service container, and the smoke test runs against the Docker Compose stack.

## API overview

All auth routes are under `/auth`.

| Method | Path | Auth required | Description |
|--------|------|---------------|-------------|
| POST | `/auth/register` | No | Create an account. Always returns `202` with a generic message |
| POST | `/auth/login` | No | Exchange credentials for an access/refresh token pair |
| POST | `/auth/refresh` | No (refresh token) | Rotate a refresh token for a new token pair |
| POST | `/auth/logout` | No (refresh token) | Revoke a single session |
| POST | `/auth/logout-all` | Yes | Revoke every active session for the current user |
| GET | `/auth/me` | Yes | Return the current user |
| GET | `/auth/sessions` | Yes | List active sessions (IP, user agent, `is_current`) |
| DELETE | `/auth/sessions/{id}` | Yes | Revoke one specific session |
| POST | `/auth/verify-email` | No (email token) | Verify an account's email address |
| POST | `/auth/resend-verification-email` | No | Issue a new verification token (always the same response) |
| POST | `/auth/forgot-password` | No | Request a password reset (always the same response) |
| POST | `/auth/reset-password` | No (reset token) | Set a new password; revokes all sessions |
| POST | `/auth/change-password` | Yes | Change password; revokes all sessions |
| DELETE | `/auth/me` | Yes | Anonymise the account and delete its sessions |
| GET | `/health` | No | Postgres and Redis connectivity check |

Full request/response schemas are available at `/docs` once the app is running.

## Project structure

```
src/sentinel/
    core/          # security primitives, rate limiting, logging, email, redis/http helpers
    database/      # SQLAlchemy models and session setup
    routes/        # FastAPI routers
    schemas/       # pydantic request/response models
    services/      # business logic, independent of the HTTP layer
    config.py      # typed settings, loaded from env vars / .env
    main.py        # app assembly: middleware, routers, startup

tests/             # pytest suite (one file per endpoint/feature area)
docs/DEPLOYMENT.md # production configuration notes
```

## Limitations

- No OAuth/social login, roles or authorisation, MFA, or CAPTCHA.
- No database migrations: tables are created with `create_all` at startup, which never alters existing tables. See `CHANGELOG.md` for schema changes between releases.
- Emails are sent from in-process background tasks with retries; there is no durable queue, so a crash can lose pending emails.
- Per-email rate limiting means someone who knows an address can keep that address's login throttled for the rate-limit window.
- Refresh-token reuse detection also revokes the session when a legitimate client sends the same refresh request twice concurrently.

See `docs/SECURITY.md` for reporting vulnerabilities and `docs/DEPLOYMENT.md` for deployment notes.

## License

MIT.