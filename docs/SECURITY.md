# Security Policy

## Supported versions

Only the latest release on `main` receives security fixes.

## Reporting a vulnerability

Please do not open a public issue. Report privately through GitHub's
"Report a vulnerability" button on the repository's Security tab, or email
melsopv@gmail.com. Include steps to reproduce and the affected version.
Reports are handled on a best-effort basis; this is a personal project with
no formal response-time commitment.

## Scope

In scope: the Sentinel service in this repository (authentication, session
handling, rate limiting, token handling).

Out of scope: vulnerabilities in third-party dependencies with no impact on
Sentinel (CI runs `pip-audit` on every push), and the development
`docker-compose.yml` stack, which publishes Postgres and Redis ports with
default credentials and is not meant for production.

## Known limitations

- Per-email rate limiting means someone who knows an email address can keep
  that address's login endpoint throttled (429) for the rate-limit window by
  continuously sending requests for it.
- Refresh-token reuse detection revokes the whole session, including when
  the "reuse" is a legitimate client that sent the same refresh request twice
  concurrently.
- Verification and reset emails are sent from in-process background tasks
  with retries; a process crash can lose emails that were still pending.
- There are no database migrations; schema changes require manual handling.
- No MFA, no CAPTCHA, no OAuth login.

See `docs/DEPLOYMENT.md` for production configuration.