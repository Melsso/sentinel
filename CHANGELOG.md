# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- Refresh-token rotation is now atomic (conditional `UPDATE`), so two concurrent `/auth/refresh` calls with the same token can no longer both succeed.
- Refresh-token reuse detection: presenting an already-rotated token revokes the whole session.
- Sessions have an absolute maximum lifetime (`SESSION_ABSOLUTE_LIFETIME_DAYS`, default 90); refreshing can no longer extend a session past it.
- Email-verification and password-reset tokens are consumed with `GETDEL` and stored in Redis as SHA-256 hashes, not raw tokens.
- Rate limiting and lockout counters use a Lua script so the counter and its TTL are set atomically.
- `X-Forwarded-For` is only honoured when the direct peer is in `TRUSTED_PROXIES` (empty by default), and the right-most untrusted hop is used.
- Account lockout is keyed on (email, client IP), so a third party can no longer lock a victim out from a different IP.
- `/register` no longer reveals whether an email is registered (same `202` response either way), and login always performs a password hash verification so response time does not reveal which accounts exist.
- The app refuses to start with a `JWT_SECRET` shorter than 32 characters or a known placeholder; `docker-compose.yml` no longer ships a default secret.
- Access tokens now carry `sid`, `typ`, `iss` and `aud` claims and are rejected as soon as their session is revoked (logout, logout-all, session revoke, password change/reset, account deletion).
- Registration races on the unique email are handled instead of returning 500.
- Emails are sent from background tasks with retry and exponential backoff (`EMAIL_SEND_ATTEMPTS`, `EMAIL_RETRY_BASE_DELAY_SECONDS`), so SMTP latency/failures no longer affect the response or reveal whether an account exists. Delivery is in-process and not durable.
- `EMAIL_BACKEND=console` is refused unless `ALLOW_CONSOLE_EMAIL=true`; unknown backends are refused; the check runs at startup.
- Audit logs no longer contain raw email addresses (a hash is logged instead) unless `LOG_PII=true`. Rate-limit events no longer log the limit key (which contained the email).
- Resetting a password now clears that account's lockout counters.
- Account deletion now anonymizes the user row (email replaced with a placeholder, password hash removed) and deletes the user's sessions, so the email can be registered again.

### Changed
- **Breaking:** `POST /auth/register` returns `202 Accepted` with a generic message instead of the created user.
- Replaced `python-jose` with `PyJWT`. This also drops the transitive `ecdsa` dependency, which carried the unfixable PYSEC-2026-1325, so the CI `pip-audit` ignore is removed.
- Password hashing/verification runs in a worker thread so Argon2 no longer blocks the event loop.
- Removed unused direct dependencies `rsa` and `cryptography`.
- Database schema changed (new `sessions.absolute_expires_at` column, new `used_refresh_tokens` table). There are no migrations; recreate the database.

### Added
- Background purge of expired sessions and sessions revoked more than `SESSION_RETENTION_DAYS` ago (`SESSION_PURGE_INTERVAL_SECONDS`).
- Sessions record IP and user agent at login; `GET /auth/sessions` returns them and marks the current session (`is_current`).
- CI runs the suite against a real Redis service container (atomicity tests) and runs the end-to-end smoke test against the docker-compose stack. The smoke test now also covers concurrent refresh and refresh-token reuse.

### Removed
- Unused scaffolding: `AuthProvider`, `UserRole`, OAuth columns on `users`, and the unused `date_of_birth` field. `provider` and `role` are no longer returned by the API.