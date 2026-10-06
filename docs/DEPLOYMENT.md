# Deployment guide

Sentinel is a standalone HTTP service backed by Postgres and Redis. The
included `docker-compose.yml` is a **development** stack; use it as a
reference, not as a production setup.

## Required configuration

| Setting | Notes |
|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://...` |
| `REDIS_URL` | Redis 7+ (the app uses `GETDEL` and Lua scripting) |
| `JWT_SECRET` | At least 32 characters; startup fails otherwise. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Rotating it invalidates every access token. |
| `EMAIL_BACKEND=smtp` + `SMTP_*` | The `console` backend is refused unless `ALLOW_CONSOLE_EMAIL=true`. |
| `FRONTEND_URL` | Base URL used in verification and reset links. |
| `CORS_ORIGINS` | Exact origins of your frontend(s). |

Everything else is documented in `.env.example`.

## Reverse proxy and client IPs

Run the app behind a TLS-terminating reverse proxy. Per-IP rate limiting,
lockout and session IP recording need the real client address:

- Set `TRUSTED_PROXIES` to the proxy's IP or CIDR. `X-Forwarded-For` is only
  read when the direct peer is in that list, and the right-most address that
  is not itself a trusted proxy is used.
- If `TRUSTED_PROXIES` is empty, the header is ignored and every client appears
  as the proxy's address, so per-IP limits become one shared bucket.
- Make sure the proxy overwrites or appends to `X-Forwarded-For` rather than
  passing through a client-supplied value unchanged.
- The Docker image starts uvicorn with `--proxy-headers`. Uvicorn only acts on
  that header for peers in `FORWARDED_ALLOW_IPS` (default `127.0.0.1`).
  Leave that variable at its default and configure `TRUSTED_PROXIES` instead.
  Sentinel then resolves the client address from whatever peer address reaches it.

The app sends a `Strict-Transport-Security` header on every response, so serve
it over HTTPS only.

## Database and Redis

- Do not publish Postgres or Redis ports; the dev compose file does so for
  convenience with default credentials.
- Tables are created at startup with `create_all`. That creates missing
  tables but never alters existing ones, and there are no migrations. When a
  release changes the schema (see `CHANGELOG.md`), migrate the database
  yourself or recreate it.
- Redis holds rate-limit counters, lockout counters and one-time tokens (as
  hashes). Losing it resets limits and invalidates pending
  verification/reset links; it does not affect sessions, which live in
  Postgres.

## Running more than one instance

Instances share all state through Postgres and Redis. Each instance runs its
own session-purge loop; the deletes are idempotent, so this is safe.

## Email

Emails are sent from in-process background tasks with retries
(`EMAIL_SEND_ATTEMPTS`, `EMAIL_RETRY_BASE_DELAY_SECONDS`). There is no
durable queue: a process crash can drop emails that were still pending.

## Logging

Logs are JSON on stdout. Audit events contain hashed email addresses unless
`LOG_PII=true`; client IPs are always logged.

## Health checks

`GET /health` returns 200 when Postgres and Redis are reachable and 503
otherwise. The Docker image's `HEALTHCHECK` uses it.