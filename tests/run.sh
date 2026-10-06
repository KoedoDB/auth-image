#!/bin/bash
# Runs the pinned Auth image (the file IMAGE) in Docker, as the Pod will run it: a non-root user, a read-only root file system, no capabilities, with ES256 keys, against
# PostgreSQL 18. It checks the behaviour KoedoDB relies on. Nothing is built: the image is upstream's (supabase/auth), used as it is.
#
#   tests/run.sh        # a few minutes; ends with "ALL OK"
#
# Needs Docker, python3 and openssl. It uses no secrets: every password and key is made up here, for the run.
#
# What is NOT checked here: Kubernetes (the Secret mount, NetworkPolicy), the gateway in front of Auth (the rate limit it has to add, see README), the mail (autoconfirm is on, so
# no mail is sent), OAuth providers, MFA, SSO.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="$(tr -d '[:space:]' < "$here/IMAGE")"
PG="postgres:18.6-trixie@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722"
H="$here/tests/jwt_helper.py"
run="kbauth$$"
net="${run}-net"
# Under $HOME: the Docker daemon has to see it (a temporary directory may be private to the shell that made it).
work="${HOME}/.${run}"; rm -rf "$work"; mkdir -p "$work"; chmod 755 "$work"
cleanup() { docker ps -aq --filter "name=^${run}-" | xargs -r docker rm -f >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; rm -rf "$work"; }
trap '[ -n "${KEEP:-}" ] || cleanup' EXIT
fail=0
check() {
  local out; out="$(eval "$2" 2>&1)"; local rc=$?
  if [ $rc = 0 ]; then echo "ok:   $1"; else echo "FAIL: $1"; fail=1; [ -n "${DEBUG:-}" ] && echo "      -> $(printf %s "$out" | head -20 | cut -c1-260)"; fi
}
note() { echo "note: $1"; }
step() { echo; echo "== $1"; }

# --- helpers -----------------------------------------------------------------------------------------------------------------------------------------------------------
jget() { python3 -c "
import sys, json
d = json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d = d[k] if isinstance(d, dict) else d[int(k)]
print(d)" "$1"; }
# req <port> <method> <path> [token] [json body]  ->  CODE and BODY
req() {
  local port=$1 method=$2 path=$3 token=${4:-} data=${5:-}
  local args=(-s -m 20 -X "$method" -w $'\n%{http_code}' "http://127.0.0.1:${port}${path}" -H 'Content-Type: application/json')
  [ -n "$token" ] && args+=(-H "Authorization: Bearer ${token}")
  [ -n "$data" ] && args+=(-d "$data")
  local out; out="$(curl "${args[@]}")"
  CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"
}
port_of() { docker port "$1" 9999/tcp | head -1 | sed 's/.*://'; }
wait_health() { for _ in $(seq 1 60); do [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "http://127.0.0.1:$1/health")" = 200 ] && return 0; sleep 1; done; return 1; }
wait_exit() { for _ in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null)" = exited ] && return 0; sleep 1; done; return 1; }
psql_db() { docker exec -i "${run}-db" psql -U postgres -v ON_ERROR_STOP=1 -At "$@"; }
now() { date +%s; }

# A container of Auth. start <name> <env file> [docker options before the image] [-- auth arguments]
HARDENED=(--user 10001:10001 --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges)
start() {
  local name="${run}-$1" envfile=$2; shift 2
  local options=() arguments=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do options+=("$1"); shift; done
  [ "${1:-}" = "--" ] && { shift; arguments=("$@"); }
  docker run -d --name "$name" --network "$net" --network-alias "$name" --env-file "$envfile" -p 127.0.0.1::9999 "${HARDENED[@]}" "${options[@]}" "$IMAGE" "${arguments[@]}" >/dev/null
}

# --- the run's keys and passwords ---------------------------------------------------------------------------------------------------------------------------------
authpw="auth-$(openssl rand -hex 12)"
jwt_secret="$(openssl rand -hex 32)"
"$H" genkey koedodb-test-1 "$work/k1.pem" "$work/k1.priv.json" "$work/k1.pub.json"
"$H" genkey koedodb-test-2 "$work/k2.pem" "$work/k2.priv.json" "$work/k2.pub.json"
"$H" genkey koedodb-other "$work/other.pem" "$work/other.priv.json" "$work/other.pub.json"   # a key Auth is never given
issuer="https://project.example/auth/v1"
cat > "$work/base.env" <<ENV
GOTRUE_API_HOST=0.0.0.0
PORT=9999
API_EXTERNAL_URL=http://${run}-auth:9999
GOTRUE_SITE_URL=http://localhost:3000
GOTRUE_DB_DRIVER=postgres
DATABASE_URL=postgres://supabase_auth_admin:${authpw}@${run}-db:5432/postgres
DB_NAMESPACE=auth
GOTRUE_JWT_SECRET=${jwt_secret}
GOTRUE_JWT_EXP=3600
GOTRUE_JWT_AUD=authenticated
GOTRUE_JWT_ISSUER=${issuer}
GOTRUE_JWT_ADMIN_ROLES=service_role
GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated
GOTRUE_MAILER_AUTOCONFIRM=true
GOTRUE_LOG_LEVEL=info
ENV
keys_env() { local joined="" f; for f in "$@"; do joined="${joined:+$joined,}$(cat "$f")"; done; printf 'GOTRUE_JWT_KEYS=[%s]\n' "$joined"; }   # keys_env <jwk file>...  (a JSON array of the files' keys, on ONE line)
{ cat "$work/base.env"; keys_env "$work/k1.priv.json"; } > "$work/auth.env"

step "PostgreSQL 18 and the preparation Auth needs"
docker network create "$net" >/dev/null
docker run -d --name "${run}-db" --network "$net" --network-alias "${run}-db" -e POSTGRES_PASSWORD="pg-$(openssl rand -hex 8)" "$PG" >/dev/null
for _ in $(seq 1 60); do docker exec "${run}-db" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done; sleep 3
check "the preparation (the role, the schema, the grant, the search path) is accepted" "psql_db -v authpw='$authpw' -q < '$here/tests/init.sql'"
docker exec "${run}-db" psql -U postgres -q -c "CREATE DATABASE bare" >/dev/null

step "Auth starts as the Pod will run it, and migrates the database"
start auth "$work/auth.env"
port="$(port_of "${run}-auth")"
check "it answers /health" "wait_health $port"
check "it runs as user 10001, on a read-only root file system" '[ "$(docker exec '"${run}"'-auth id -u)" = 10001 ] && [ "$(docker inspect -f "{{.HostConfig.ReadonlyRootfs}}" '"${run}"'-auth)" = true ]'
check "the migrations ran (auth.schema_migrations is not empty)" '[ "$(psql_db -c "select count(*) from auth.schema_migrations")" -gt 50 ]'
check "the tables are there (users, identities, sessions, refresh_tokens, mfa_factors, one_time_tokens, audit_log_entries)" \
  '[ "$(psql_db -c "select count(*) from information_schema.tables where table_schema = '"'"'auth'"'"' and table_name in ('"'"'users'"'"','"'"'identities'"'"','"'"'sessions'"'"','"'"'refresh_tokens'"'"','"'"'mfa_factors'"'"','"'"'one_time_tokens'"'"','"'"'audit_log_entries'"'"')")" = 7 ]'
check "auth.uid(), auth.role(), auth.email() and auth.jwt() exist (the functions an RLS policy uses)" \
  '[ "$(psql_db -c "select string_agg(proname, '"'"','"'"' order by proname) from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = '"'"'auth'"'"' and proname in ('"'"'uid'"'"','"'"'role'"'"','"'"'email'"'"','"'"'jwt'"'"')")" = "email,jwt,role,uid" ]'
check "the schema belongs to the role Auth connects as, and nothing was made in public" \
  '[ "$(psql_db -c "select tableowner from pg_tables where schemaname = '"'"'auth'"'"' and tablename = '"'"'users'"'"'")" = supabase_auth_admin ] && [ "$(psql_db -c "select count(*) from pg_tables where schemaname = '"'"'public'"'"'")" = 0 ]'

step "Sign-up and the token: ES256, the keys in the JWKS, the claims"
email="user1-$(openssl rand -hex 4)@example.com"; password="correct-horse-$(openssl rand -hex 4)"
req "$port" POST /signup "" "{\"email\":\"$email\",\"password\":\"$password\"}"; signup_code="$CODE"
access="$(printf %s "$BODY" | jget access_token)"; refresh="$(printf %s "$BODY" | jget refresh_token)"; uid="$(printf %s "$BODY" | jget user.id)"
req "$port" GET /.well-known/jwks.json; jwks_code="$CODE"; printf %s "$BODY" > "$work/jwks.json"
check "a sign-up with autoconfirm gives a session at once" '[ "$signup_code" = 200 ] && [ -n "$access" ] && [ -n "$refresh" ]'
check "the access token is ES256, with the kid of the key Auth was given" '[ "$("$H" decode "$access" | jget header.alg)" = ES256 ] && [ "$("$H" decode "$access" | jget header.kid)" = koedodb-test-1 ]'
check "the JWKS has the public key and no private part (no d)" '[ "$jwks_code" = 200 ] && ! grep -q "\"d\"" "$work/jwks.json" && [ "$(jget keys.0.kid < "$work/jwks.json")" = koedodb-test-1 ]'
check "the signature verifies against the key in the JWKS (a verifier that is not Auth's own)" '"$H" verify "$work/jwks.json" "$access" >/dev/null'
claims_ok() {
  "$H" decode "$access" | python3 -c '
import sys, json
c = json.load(sys.stdin)["claims"]
want = {"aud": "authenticated", "role": "authenticated", "sub": sys.argv[1], "email": sys.argv[2], "iss": sys.argv[3]}
bad = {k: c.get(k) for k, v in want.items() if c.get(k) != v}
if c["exp"] - c["iat"] != 3600:
    bad["exp-iat"] = c["exp"] - c["iat"]
if bad:
    sys.exit("wrong claims: %s" % bad)' "$uid" "$email" "$issuer"
}
check "the claims: aud and role authenticated, sub is the user, the email, iss is GOTRUE_JWT_ISSUER, exp is iat + 3600" claims_ok
check "auth.uid() gives the sub of the claims (what an RLS policy compares with)" \
  '[ "$(psql_db -c "select set_config('"'"'request.jwt.claims'"'"', '"'"'{\"sub\":\"$uid\"}'"'"', false); select auth.uid()::text" | tail -1)" = "$uid" ]'

step "Without GOTRUE_JWT_DEFAULT_GROUP_NAME the role of a user is empty"
grep -v '^GOTRUE_JWT_DEFAULT_GROUP_NAME=' "$work/auth.env" > "$work/norole.env"
start norole "$work/norole.env"; p0="$(port_of "${run}-norole")"; wait_health "$p0"
req "$p0" POST /signup "" "{\"email\":\"norole-$(openssl rand -hex 3)@example.com\",\"password\":\"correct-horse-battery\"}"
check "a user's token has an EMPTY role claim (PostgREST would have no role to switch to): KoedoDB must set GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated" '[ "$("$H" decode "$(printf %s "$BODY" | jget access_token)" | jget claims.role)" = "" ]'
docker rm -f "${run}-norole" >/dev/null

step "Which tokens Auth accepts: only the ones signed with its keys"
now_s="$(now)"; claims() { printf '{"role":"%s","aud":"authenticated","iss":"%s","iat":%s,"exp":%s}' "$1" "$issuer" "$now_s" "$2"; }
service="$("$H" sign "$work/k1.pem" koedodb-test-1 "$(claims service_role $((now_s + 3600)))")"
anon="$("$H" sign "$work/k1.pem" koedodb-test-1 "$(claims anon $((now_s + 3600)))")"
req "$port" GET /user "$access"; user_code="$CODE"; user_email="$(printf %s "$BODY" | jget email)"
check "/user with the access token answers with the user" '[ "$user_code" = 200 ] && [ "$user_email" = "$email" ]'
req "$port" GET /admin/users "$service"; check "the admin API accepts a service_role token signed with the key (the key KoedoDB gives a Project)" '[ "$CODE" = 200 ]'
req "$port" GET /admin/users "$anon"; check "the admin API refuses an anon token signed with the same key (403)" '[ "$CODE" = 403 ]'
req "$port" GET /admin/users ""; check "the admin API refuses a request with no token (401)" '[ "$CODE" = 401 ]'
req "$port" GET /admin/users "$access"; check "the admin API refuses a signed-in user's token (403)" '[ "$CODE" = 403 ]'
other="$("$H" sign "$work/other.pem" koedodb-other "$(claims service_role $((now_s + 3600)))")"
req "$port" GET /admin/users "$other"; check "a service_role token signed with a key Auth does not have is refused" '[ "$CODE" != 200 ]'
forged="$("$H" sign "$work/other.pem" koedodb-test-1 "$(claims service_role $((now_s + 3600)))")"
req "$port" GET /admin/users "$forged"; check "a token that names Auth's kid but is signed by another key is refused" '[ "$CODE" != 200 ]'
expired="$("$H" sign "$work/k1.pem" koedodb-test-1 "$(claims service_role $((now_s - 60)))")"
req "$port" GET /admin/users "$expired"; check "an expired service_role token is refused" '[ "$CODE" != 200 ]'
python3 - "$service" > "$work/tampered" <<'PY'
import sys
h, p, s = sys.argv[1].split(".")
print(h + "." + p[:-2] + ("AA" if not p.endswith("AA") else "BB") + "." + s)
PY
req "$port" GET /admin/users "$(cat "$work/tampered")"; check "a token whose payload was changed after signing is refused" '[ "$CODE" != 200 ]'
hs="$(python3 - "$jwt_secret" "$now_s" <<'PY'
import sys, hmac, hashlib, base64, json
secret, now = sys.argv[1], int(sys.argv[2])
b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
head = b(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()); body = b(json.dumps({"role": "service_role", "aud": "authenticated", "iat": now, "exp": now + 3600}).encode())
print(head + "." + body + "." + b(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()))
PY
)"
req "$port" GET /admin/users "$hs"; check "GOTRUE_JWT_SECRET is required but is no key: an HS256 token signed with it is refused, service_role or not" '[ "$CODE" != 200 ]'

step "Log in, refresh, log out, and a restart"
req "$port" POST "/token?grant_type=password" "" "{\"email\":\"$email\",\"password\":\"$password\"}"; login_code="$CODE"; refresh2="$(printf %s "$BODY" | jget refresh_token)"
check "the right password logs in" '[ "$login_code" = 200 ]'
req "$port" POST "/token?grant_type=password" "" "{\"email\":\"$email\",\"password\":\"wrong-$password\"}"; check "a wrong password is refused (400)" '[ "$CODE" = 400 ]'
req "$port" POST "/token?grant_type=refresh_token" "" "{\"refresh_token\":\"$refresh2\"}"; refresh_code="$CODE"; access3="$(printf %s "$BODY" | jget access_token)"; refresh3="$(printf %s "$BODY" | jget refresh_token)"
check "a refresh token gives a new access token and a new refresh token" '[ "$refresh_code" = 200 ] && [ "$access3" != "$access" ] && [ "$refresh3" != "$refresh2" ]'
req "$port" POST /logout "$access3"; logout_code="$CODE"
req "$port" POST "/token?grant_type=refresh_token" "" "{\"refresh_token\":\"$refresh3\"}"
check "after /logout the session is gone: its refresh token is refused" '[ "$logout_code" = 204 ] && [ "$CODE" = 400 ]'
docker restart "${run}-auth" >/dev/null; port="$(port_of "${run}-auth")"; wait_health "$port"
req "$port" POST "/token?grant_type=password" "" "{\"email\":\"$email\",\"password\":\"$password\"}"
check "after a restart the user is still there and logs in (the data is in the database, Auth keeps none)" '[ "$CODE" = 200 ]'

step "Many wrong passwords: Auth has no limit for them"
codes=""; for i in $(seq 1 40); do req "$port" POST "/token?grant_type=password" "" "{\"email\":\"$email\",\"password\":\"wrong-$i\"}"; codes="$codes $CODE"; done
check "40 wrong passwords in a row all get 400, never 429: the gateway has to limit /auth/v1/token (README)" '[ "$(echo $codes | tr " " "\n" | sort -u)" = 400 ]'
req "$port" POST "/token?grant_type=password" "" "{\"email\":\"$email\",\"password\":\"$password\"}"
check "and the right password still logs in afterwards (no lockout of the user either)" '[ "$CODE" = 200 ]'

step "Another Auth on the same database: sign-up turned off"
{ cat "$work/auth.env"; echo "GOTRUE_DISABLE_SIGNUP=true"; } > "$work/nosignup.env"
start nosignup "$work/nosignup.env"; p2="$(port_of "${run}-nosignup")"; wait_health "$p2"
req "$p2" POST /signup "" "{\"email\":\"nope-$(openssl rand -hex 3)@example.com\",\"password\":\"correct-horse-battery\"}"; check "with GOTRUE_DISABLE_SIGNUP=true a sign-up is refused" '[ "$CODE" -ge 400 ] && [ "$CODE" -lt 500 ]'
req "$p2" GET /settings; check "/settings says so" '[ "$(printf %s "$BODY" | jget disable_signup)" = True ]'
req "$p2" POST "/token?grant_type=password" "" "{\"email\":\"$email\",\"password\":\"$password\"}"; check "an existing user can still log in" '[ "$CODE" = 200 ]'

step "A configuration directory is watched: a change takes effect without a restart"
mkdir -p "$work/cfg"; cp "$work/base.env" "$work/cfg/00-base.env"; keys_env "$work/k1.priv.json" > "$work/cfg/20-keys.env"
printf 'GOTRUE_MAILER_AUTOCONFIRM=true\nGOTRUE_DISABLE_SIGNUP=false\n' > "$work/cfg/10-mail.env"
: > "$work/empty.env"
start reload "$work/empty.env" -v "$work/cfg:/cfg:ro" -- auth -d /cfg
p3="$(port_of "${run}-reload")"; wait_health "$p3"
setting() { req "$p3" GET /settings; printf %s "$BODY" | jget "$1"; }
wait_setting() { for _ in $(seq 1 40); do [ "$(setting "$1")" = "$2" ] && return 0; sleep 1; done; return 1; }
before="$(setting disable_signup)"
printf 'GOTRUE_MAILER_AUTOCONFIRM=false\nGOTRUE_DISABLE_SIGNUP=true\n' > "$work/cfg/10-mail.env"
check "a change in the directory takes effect without a restart (sign-up off, a few seconds later)" '[ "$before" = False ] && wait_setting disable_signup True && [ "$(docker inspect -f "{{.RestartCount}} {{.State.Running}}" '"${run}"'-reload)" = "0 true" ]'
# What Auth does with a line that is taken out: the value it had stays. A setting is put back by writing its value, not by deleting the line.
printf 'GOTRUE_MAILER_AUTOCONFIRM=true\n' > "$work/cfg/10-mail.env"
wait_setting mailer_autoconfirm True
sleep 8
check "a line taken out of the directory does NOT go back to its default: sign-up stays off (write the value instead, README)" '[ "$(setting disable_signup)" = True ]'
printf 'GOTRUE_MAILER_AUTOCONFIRM=true\nGOTRUE_DISABLE_SIGNUP=false\n' > "$work/cfg/10-mail.env"
check "written again as false, it is back" 'wait_setting disable_signup False'

step "Key rotation: the old public key stays for verification, then goes"
rot_email="rot-$(openssl rand -hex 4)@example.com"
req "$p3" POST /signup "" "{\"email\":\"$rot_email\",\"password\":\"correct-horse-battery\"}"; old_token="$(printf %s "$BODY" | jget access_token)"
check "before the rotation a token is signed with key 1" '[ "$("$H" decode "$old_token" | jget header.kid)" = koedodb-test-1 ]'
keys_env "$work/k2.priv.json" "$work/k1.pub.json" > "$work/cfg/20-keys.env"
kids() { curl -s -m 5 "http://127.0.0.1:$p3/.well-known/jwks.json" | python3 -c "import sys,json; print(','.join(sorted(k['kid'] for k in json.load(sys.stdin)['keys'])))"; }
for _ in $(seq 1 40); do [ "$(kids)" = "koedodb-test-1,koedodb-test-2" ] && break; sleep 1; done
check "the JWKS lists both keys, public only" '[ "$(kids)" = "koedodb-test-1,koedodb-test-2" ] && ! curl -s -m 5 "http://127.0.0.1:'"$p3"'/.well-known/jwks.json" | grep -q "\"d\""'
req "$p3" GET /user "$old_token"; check "a token signed with the old key is still accepted while its public key is listed" '[ "$CODE" = 200 ]'
req "$p3" POST "/token?grant_type=password" "" "{\"email\":\"$rot_email\",\"password\":\"correct-horse-battery\"}"; new_token="$(printf %s "$BODY" | jget access_token)"
check "a new token is signed with key 2" '[ "$("$H" decode "$new_token" | jget header.kid)" = koedodb-test-2 ]'
curl -s -m 5 "http://127.0.0.1:$p3/.well-known/jwks.json" > "$work/jwks2.json"
check "and it verifies against the JWKS" '"$H" verify "$work/jwks2.json" "$new_token" >/dev/null'
keys_env "$work/k2.priv.json" > "$work/cfg/20-keys.env"
for _ in $(seq 1 40); do [ "$(kids)" = "koedodb-test-2" ] && break; sleep 1; done
req "$p3" GET /user "$old_token"; check "once the old key is removed the old token is refused (403 bad_jwt, unrecognized kid)" '[ "$(kids)" = "koedodb-test-2" ] && [ "$CODE" = 403 ] && printf %s "$BODY" | grep -q bad_jwt'
req "$p3" GET /user "$new_token"; check "and the new token is accepted" '[ "$CODE" = 200 ]'

step "What must stop Auth, and stop it loudly"
fatal() { docker logs "${run}-$1" 2>&1 | grep -c '"level":"fatal"'; }
sed "s#/postgres\$#/bare#" "$work/auth.env" > "$work/bare.env"
start bare "$work/bare.env"; wait_exit "${run}-bare"
check "a database without the schema and the CREATE grant: Auth exits with a fatal error and does not run" '[ "$(docker inspect -f "{{.State.Status}}" '"${run}"'-bare)" = exited ] && [ "$(fatal bare)" -ge 1 ]'
sed "s#:${authpw}@#:wrong-password@#" "$work/auth.env" > "$work/badpw.env"
start badpw "$work/badpw.env"; wait_exit "${run}-badpw"
check "a wrong database password: it exits with a fatal error" '[ "$(fatal badpw)" -ge 1 ]'
grep -v '^GOTRUE_JWT_SECRET=' "$work/auth.env" > "$work/nosecret.env"
start nosecret "$work/nosecret.env"; wait_exit "${run}-nosecret"
check "without GOTRUE_JWT_SECRET, even with asymmetric keys: it exits and says which key is missing" '[ "$(docker logs '"${run}"'-nosecret 2>&1 | grep -c GOTRUE_JWT_SECRET)" -ge 1 ]'

echo
[ "$fail" = 0 ] && echo "ALL OK" || { echo "SOME CHECKS FAILED"; exit 1; }
