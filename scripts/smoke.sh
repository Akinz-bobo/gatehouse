#!/usr/bin/env bash
# Walks the main flows against a running stack, the way a client would.
# Usage: ./scripts/smoke.sh [base-url]
set -euo pipefail

BASE="${1:-http://localhost:4000}"
EMAIL="smoke-$(date +%s)-$RANDOM@example.com"
PASSWORD='correct horse battery staple'

step() { printf '  %-58s' "$1"; }
ok() { echo ok; }
fail() { echo "FAILED: $1"; exit 1; }

# Prints the status code; the body goes to $BODY.
BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT
call() {
  local method=$1 path=$2 data=${3:-} token=${4:-}
  local args=(--silent --output "$BODY" --write-out '%{http_code}' --request "$method")
  [ -n "$data" ] && args+=(--header 'content-type: application/json' --data "$data")
  [ -n "$token" ] && args+=(--header "authorization: Bearer $token")
  curl "${args[@]}" "$BASE$path"
}
expect() { [ "$1" = "$2" ] || fail "expected HTTP $2, got $1: $(cat "$BODY")"; }

echo "Smoke test against $BASE"

step 'service is ready'
expect "$(call GET /readyz)" 200; ok

step 'register'
expect "$(call POST /v1/auth/register "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")" 201; ok

step 'weak password is refused'
expect "$(call POST /v1/auth/register '{"email":"weak@example.com","password":"short"}')" 422; ok

step 'wrong password is refused'
expect "$(call POST /v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"not the password\"}")" 401; ok

step 'sign in'
expect "$(call POST /v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")" 200
ACCESS=$(jq -r .accessToken "$BODY"); REFRESH=$(jq -r .refreshToken "$BODY"); ok

step 'access token works'
expect "$(call GET /v1/auth/me '' "$ACCESS")" 200
[ "$(jq -r .user.email "$BODY")" = "$EMAIL" ] || fail 'wrong user returned'; ok

step 'no token is refused'
expect "$(call GET /v1/auth/me)" 401; ok

step 'public keys are published without private material'
expect "$(call GET /.well-known/jwks.json)" 200
[ "$(jq '[.keys[] | has("d")] | any' "$BODY")" = false ] || fail 'private key material in JWKS'; ok

step 'refresh rotates the token'
expect "$(call POST /v1/auth/refresh "{\"refreshToken\":\"$REFRESH\"}")" 200
NEW_ACCESS=$(jq -r .accessToken "$BODY"); ok

step 'replaying the old refresh token ends the session'
expect "$(call POST /v1/auth/refresh "{\"refreshToken\":\"$REFRESH\"}")" 401
[ "$(jq -r .error.code "$BODY")" = refresh_token_reused ] || fail 'replay not detected'
expect "$(call GET /v1/auth/me '' "$NEW_ACCESS")" 401; ok

step 'an ordinary user cannot rotate signing keys'
expect "$(call POST /v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")" 200
ACCESS=$(jq -r .accessToken "$BODY")
expect "$(call POST /v1/admin/keys/rotate '' "$ACCESS")" 403; ok

step 'sign out'
expect "$(call POST /v1/auth/logout '' "$ACCESS")" 204
expect "$(call GET /v1/auth/me '' "$ACCESS")" 401; ok

echo 'All smoke checks passed.'
