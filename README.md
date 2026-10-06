# Auth image

KoedoDB runs [Supabase Auth](https://github.com/supabase/auth) (formerly GoTrue) **as upstream publishes it**. Nothing is built or patched here: this directory pins the image, says how KoedoDB runs it, and tests what KoedoDB relies on.

This is not an official Supabase repository, and KoedoDB is not affiliated with Supabase. "Supabase" belongs to its owner.

## The image

The file `IMAGE` holds the image, by tag and by digest of the multi-architecture index:

```
supabase/auth:v2.197.0@sha256:1736a63078f5922b198c4cbe50f80ab9a2d3b54fe8b7b6cfb2e9dc5dbbc12c6b
```

`supabase/gotrue` is the same image under its old name (the same digest), and so is `ghcr.io/supabase/auth`.

To update it, change the tag and the digest together (`docker buildx imagetools inspect supabase/auth:<tag>`), then run `tests/run.sh`. Read the [release notes](https://github.com/supabase/auth/releases) and the [security advisories](https://github.com/supabase/auth/security-advisories) first.

The image runs as user `supabase` (uid 1000). KoedoDB runs it as uid 10001, with a read-only root file system, no capabilities and no new privileges; the test runs exactly that.

## How it is run

```sh
docker run --user 10001:10001 --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --env-file auth.env <IMAGE>
```

Add `auth -d /config` to read the settings from a directory of `.env` files instead (see "A configuration directory", below).

## What the database needs first

Auth migrates its own `auth` schema, but it needs these before it starts (`tests/init.sql`, from `supabase/auth`'s own `hack/init_postgres.sql`):

```sql
CREATE USER supabase_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION PASSWORD '…';
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION supabase_auth_admin;
GRANT CREATE ON DATABASE postgres TO supabase_auth_admin;
ALTER USER supabase_auth_admin SET search_path = 'auth';
```

The role `postgres` has to exist too: one of Auth's migrations (`20240612123726`) grants to it. The official PostgreSQL image has it. Without the preparation, Auth stops with a fatal error during the migrations and does not run (the test checks a database without the schema and the grant, and a wrong password).

## Settings

| Variable | Value | Note |
|---|---|---|
| `DATABASE_URL` | `postgres://supabase_auth_admin:<password>@<host>:5432/postgres` | The role of the preparation above. |
| `DB_NAMESPACE` | `auth` | The schema. |
| `GOTRUE_DB_DRIVER` | `postgres` | |
| `GOTRUE_JWT_KEYS` | a JSON array of JWKs, on one line | The signing keys: an ES256 key with `"key_ops":["sign","verify"]` and its private part (`d`). The JWKS at `/.well-known/jwks.json` shows the public parts only. |
| `GOTRUE_JWT_SECRET` | a random string | **Required even with `GOTRUE_JWT_KEYS`**, but it is no key for API tokens: an HS256 token signed with it is refused (tested). Give each project its own. |
| `GOTRUE_JWT_DEFAULT_GROUP_NAME` | `authenticated` | **Without it the `role` claim of a user's token is empty** (tested), and PostgREST has no role to switch to. Upstream warns that this setting is deprecated, but it is what sets the role. |
| `GOTRUE_JWT_ISSUER` | the issuer the gateway checks | The `iss` claim is set only when this is. |
| `GOTRUE_JWT_ADMIN_ROLES` | `service_role` | The roles allowed on `/admin/*`. |
| `GOTRUE_JWT_EXP`, `GOTRUE_JWT_AUD` | `3600`, `authenticated` | |
| `API_EXTERNAL_URL`, `GOTRUE_SITE_URL` | | Required. |
| `GOTRUE_API_HOST`, `PORT` | `0.0.0.0`, `9999` | |
| `GOTRUE_MAILER_AUTOCONFIRM` | `true` or `false` | With `true` no mail is sent at sign-up. |
| `GOTRUE_DISABLE_SIGNUP` | `true` or `false` | |

## Things to know

- **There is no limit on password sign-ins.** Forty wrong passwords in a row all got 400, never 429, and the right password still worked afterwards. Auth limits mail sending, verification, token refresh, SSO, anonymous users, OTP and a few more, but not `POST /token?grant_type=password`. A gateway in front of Auth has to limit it (per address, and per account).
- **A configuration directory is watched.** With `auth -d <directory>` a change in the directory's files takes effect in a few seconds, without a restart. **A line that is taken out does not go back to its default: the value it had stays.** Put a setting back by writing its value (`GOTRUE_DISABLE_SIGNUP=false`), not by deleting the line.
- **Rotating the signing key:** put the new private key first and the old key as a public JWK (`"key_ops":["verify"]`) after it. New tokens are signed with the new key, tokens signed with the old one are still accepted, and the JWKS lists both. When the old tokens have expired, take the old key out: a token signed with it is refused (403, `bad_jwt`, "unrecognized JWT kid").
- **The admin API** (`/admin/*`) takes a token whose `role` claim is in `GOTRUE_JWT_ADMIN_ROLES`, signed with one of the keys. An anon token, a signed-in user's token, a token signed with another key (even with the right `kid`), an expired one and one whose payload was changed are all refused.
- **A session ends at `/logout`**: its refresh token is refused afterwards. The access token stays valid until it expires (it is a signed token, and Auth does not look anything up for it).
- Auth keeps no state of its own: after a restart the users are still there and log in.

## What the tests check

`tests/run.sh` starts PostgreSQL 18 (pinned by digest), prepares it, and starts the image as described above, then checks:

- the migrations run (the tables and the functions `auth.uid()`, `auth.role()`, `auth.email()`, `auth.jwt()` are there, the schema belongs to the role Auth connects as, nothing is made in `public`), and `auth.uid()` gives the `sub` of the claims;
- the token: ES256, the `kid`, the claims (`aud`, `role`, `sub`, `email`, `iss`, `exp - iat`), the JWKS has no private part, and the signature verifies against the JWKS with a verifier that is not Auth's own (`tests/jwt_helper.py`, which needs only Python's standard library and `openssl`);
- which tokens are accepted and which are not (above);
- sign-up, log in, wrong password, refresh, log out, and a restart;
- forty wrong passwords (above);
- sign-up turned off;
- the configuration directory (a change takes effect, a removed line does not go back);
- key rotation (above);
- the failures that must stop Auth, and stop it loudly: a database without the preparation, a wrong database password, no `GOTRUE_JWT_SECRET`.

It needs Docker, Python 3 and `openssl`, and uses no secrets: every password and key is made up for the run.

## Not checked

Kubernetes (the Secret mount, network policy), the gateway in front of Auth (the rate limit it has to add), mail (autoconfirm is on, so none is sent), OAuth providers, MFA, SSO, and Auth behind a connection pooler.

## License

Copyright (c) 2026 RadarWorks LLC. The files in this repository (`IMAGE`, the tests and this documentation) are licensed under the [MIT License](LICENSE), the same license as [Supabase Auth](https://github.com/supabase/auth) itself. The Auth image is upstream's, under its own license.
