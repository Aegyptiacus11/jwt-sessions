# tandem-auth

First-party authentication for FastAPI: email and password sign-in,
short-lived access tokens, and refresh tokens that rotate on every use and
give themselves away when stolen.

It is for applications that own their users and do not want an identity
provider. Authorization - who may do what - is deliberately not here; it
belongs to the application.

> Status: pre-release (`0.1.0.dev0`), extracted from a production application;
> the API may still change before 0.1.0. MIT licensed.

## Installing

Not on PyPI - install from this repository, pinned to a commit:

```bash
uv add "tandem-auth[fastapi,sqlalchemy] @ git+https://github.com/Aegyptiacus11/tandem-auth@<commit>"
```

(`pip install` takes the same URL.)

## Using it

```python
from tandem_auth import AccessTokens, Auth, RefreshTokens
from tandem_auth.fastapi import auth_router, bearer_claims
from tandem_auth.sqlalchemy_store import SQLAlchemyRefreshStore, refresh_tables

families, tokens = refresh_tables(Base.metadata)  # on your own metadata
auth = Auth(
    users=MyUsers(),  # by_login / by_id -> AuthUser
    access=AccessTokens(settings.jwt_secret),
    refresh=RefreshTokens(SQLAlchemyRefreshStore(sessionmaker, families, tokens)),
)
app.include_router(auth_router(auth), prefix="/api/v1")
current_claims = bearer_claims(auth)  # a dependency: the verified claims
```

`examples/demo_app.py` is a complete, runnable one:
`uv run uvicorn examples.demo_app:app`.

## The contract

| | Request | Response |
|---|---|---|
| `POST /auth/login` | `{"email", "password"}` | `{"access_token", "token_type"}` + the refresh cookie |
| `POST /auth/refresh` | the refresh cookie | a new access token + the rotated cookie |
| `POST /auth/logout` | the refresh cookie | `204`; that session is revoked, the cookie cleared |
| `POST /auth/logout-all` | `Authorization: Bearer` | `204`; every session of the user is revoked |

- **The access token** is a JWT (HS256, 15 minutes by default), sent as
  `Authorization: Bearer`. It is never in a cookie, so no request is authorised
  by a cookie alone.
- **The refresh token** is an opaque random value that only ever travels in an
  `httpOnly`, `SameSite=Lax` cookie scoped to the auth endpoints. JavaScript
  never sees it, so a script injected into the page cannot take it away.

### What a client has to do

A browser client is small - there is no client library, and the contract is
all it needs:

- Keep the access token in memory, not in storage.
- Call the auth endpoints with `credentials: "include"`, so the cookie travels.
- On load, `POST /auth/refresh` to restore a session; a 401 means signed out.
- On a 401 from the API, refresh **once** and retry; if the refresh fails, the
  session is gone.
- Never run two refreshes at once from one page: the server spends a refresh
  token on use, and the second would look like a replay (see below). Share one
  in-flight refresh between everything that needs a token.
- Renewing a minute before the access token's `exp` saves the first request
  after an idle spell a round trip.

## What happens to a stolen refresh token

A sign-in starts a **family** of refresh tokens. Each refresh spends the
token presented and issues its successor. A spent token presented again means
two parties hold it - the user and whoever copied it - so the whole family is
revoked: both are signed out, and the copy is dead.

A stateless refresh JWT, the usual alternative, can do none of this: a copied
one keeps working until it expires, however often its owner refreshes, and
signing out only deletes the owner's copy.

Two tabs refreshing at the same instant would look like a replay, so a spent
token presented again within `reuse_grace_seconds` (10 s by default; 0 turns it
off) gets a successor instead. That window is open to a thief as well, if they
replay within those seconds of the real refresh.

Only the SHA-256 of a refresh token is stored, so a copy of the table holds
nothing that can be presented.

## Also

- Signing in with an unknown email costs the same argon2 verification as a
  wrong password, so response time does not say which addresses have accounts.
- Passwords over 1 KB are refused before hashing.
- The signing secret must be at least 32 bytes, and the JWT algorithm is pinned
  on verification, never read from the token.
- A deactivated account's session ends at its next refresh; its current access
  token runs out within the access TTL. `Auth.logout_everywhere` ends every
  session at once - call it on deactivation and on a password change.
- `RefreshStore.purge` drops expired tokens; run it now and then (on start-up
  is enough for most applications).

## Development

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```
