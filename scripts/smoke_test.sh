#!/usr/bin/env bash
# Live smoke test against the real docker-compose stack (Postgres + Redis
# + app) -- not the SQLite/FakeRedis test suite. Run this against actual
# running containers to confirm the whole thing works end to end for real.
#
# Usage:
#   docker compose up --build -d
#   ./scripts/smoke_test.sh
#   docker compose down -v   # cleanup when you're done
#
# Requires: curl, jq

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
EMAIL="smoketest-$(date +%s)@example.com"
PASSWORD="Password123!"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

echo "== 1. Health check =="
HEALTH=$(curl -sf "$BASE_URL/health")
echo "$HEALTH" | jq .
[ "$(echo "$HEALTH" | jq -r .status)" = "ok" ] || fail "health check did not report ok"
pass "app, Postgres, and Redis are all reachable"

echo
echo "== 2. Register =="
REGISTER=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "$REGISTER" | jq .
USER_ID=$(echo "$REGISTER" | jq -r .id)
[ "$USER_ID" != "null" ] || fail "registration did not return a user id"
pass "registered user $USER_ID"

echo
echo "== 3. Pull the verification token out of the app's logs =="
# The console email backend logs the email instead of sending it -- this
# is the same "click the link" step a real inbox would give you.
sleep 1
TOKEN=$(docker compose logs app --no-color --no-log-prefix \
  | grep '"event": "email_dispatched"' \
  | grep "$EMAIL" \
  | tail -1 \
  | sed -E 's/^[^{]*//' \
  | jq -r '.body' \
  | grep -oE 'token=[A-Za-z0-9_-]+' \
  | cut -d= -f2)
[ -n "$TOKEN" ] || fail "could not find a verification token in the app logs"
pass "found verification token: ${TOKEN:0:12}..."

echo
echo "== 4. Verify email =="
VERIFY=$(curl -s -X POST "$BASE_URL/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}")
echo "$VERIFY" | jq .
[ "$(echo "$VERIFY" | jq -r .is_verified)" = "true" ] || fail "email was not marked verified"
pass "email verified"

echo
echo "== 5. Login =="
LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "$LOGIN" | jq .
ACCESS_TOKEN=$(echo "$LOGIN" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$LOGIN" | jq -r .refresh_token)
[ "$ACCESS_TOKEN" != "null" ] || fail "login did not return an access token"
pass "logged in"

echo
echo "== 6. GET /me =="
ME=$(curl -s "$BASE_URL/auth/me" -H "Authorization: Bearer $ACCESS_TOKEN")
echo "$ME" | jq .
[ "$(echo "$ME" | jq -r .email)" = "$EMAIL" ] || fail "/me did not return the expected user"
pass "/me returned the right user"

echo
echo "== 7. GET /sessions =="
SESSIONS=$(curl -s "$BASE_URL/auth/sessions" -H "Authorization: Bearer $ACCESS_TOKEN")
echo "$SESSIONS" | jq .
[ "$(echo "$SESSIONS" | jq 'length')" = "1" ] || fail "expected exactly one active session"
pass "one active session listed"

echo
echo "== 8. Refresh token rotation =="
REFRESH=$(curl -s -X POST "$BASE_URL/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")
echo "$REFRESH" | jq .
NEW_REFRESH_TOKEN=$(echo "$REFRESH" | jq -r .refresh_token)
[ "$NEW_REFRESH_TOKEN" != "$REFRESH_TOKEN" ] || fail "refresh token did not rotate"
pass "refresh token rotated"

echo
echo "== 9. Old refresh token is now invalid =="
OLD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")
[ "$OLD_STATUS" = "401" ] || fail "old refresh token should have been rejected (got $OLD_STATUS)"
pass "old refresh token correctly rejected"

echo
echo "== 10. Logout =="
LOGOUT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/auth/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$NEW_REFRESH_TOKEN\"}")
[ "$LOGOUT_STATUS" = "204" ] || fail "logout did not return 204 (got $LOGOUT_STATUS)"
pass "logged out"

echo
echo "== 11. Rate limiting (6 wrong-password attempts) =="
for _ in 1 2 3 4 5; do
  curl -s -o /dev/null -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"wrong\"}"
done
RATE_LIMITED_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"wrong\"}")
[ "$RATE_LIMITED_STATUS" = "429" ] || fail "expected 429 after exceeding the login rate limit (got $RATE_LIMITED_STATUS)"
pass "rate limiting kicked in as expected"

echo
echo "== 12. Confirm the data actually landed in real Postgres =="
docker compose exec -T postgres psql -U sentinel -d sentinel -c \
  "select id, email, is_verified, provider from users where email = '$EMAIL';"

echo
echo "All smoke test checks passed."