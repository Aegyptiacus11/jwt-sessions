# tandem-auth

First-party authentication for a FastAPI API and a React front end, as two
packages that implement one contract:

- **the Python package** (`python/`) - password sign-in, short-lived access tokens, and
  refresh tokens that rotate on every use and give themselves away when stolen.
- **the JavaScript package** (`js/`) - the React side: the session, sign-in and sign-out,
  renewal before expiry, and one refresh on a 401.

It is for applications that own their users and do not want an identity
provider: one API, one front end, email and password. Authorization - who may
do what - is deliberately not here; it belongs to the application.

> Status: pre-release (`0.1.0.dev0`). Extracted from a production application,
> but the API may still change before 0.1.0. MIT licensed.

## The contract

| | Request | Response |
|---|---|---|
| `POST /auth/login` | `{"email", "password"}` | `{"access_token", "token_type"}` + the refresh cookie |
| `POST /auth/refresh` | the refresh cookie | a new access token + the rotated cookie |
| `POST /auth/logout` | the refresh cookie | `204`; that session is revoked, the cookie cleared |
| `POST /auth/logout-all` | `Authorization: Bearer` | `204`; every session of the user is revoked |

- **The access token** is a JWT (HS256, 15 minutes by default) held in memory
  by the client and sent as `Authorization: Bearer`. It is never in a cookie,
  so no request is authorised by a cookie alone.
- **The refresh token** is an opaque random value that only ever travels in an
  `httpOnly`, `SameSite=Lax` cookie scoped to the auth endpoints. JavaScript
  never sees it, so a script injected into the page cannot take it away.

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
  token runs out within the access TTL.

## Installing

Not on PyPI or npm yet - install from this repository, pinned to a commit:

```bash
# Python (uv; pip takes the same URL)
uv add "tandem-auth[fastapi,sqlalchemy] @ git+https://github.com/Aegyptiacus11/tandem-auth@<commit>#subdirectory=python"

# JavaScript (pnpm builds it on install)
pnpm add "tandem-auth@github:Aegyptiacus11/tandem-auth#<commit>&path:/js"
```

## Using it

**Python**:

```python
from tandem_auth import AccessTokens, Auth, RefreshTokens
from tandem_auth.fastapi import auth_router, bearer_claims
from tandem_auth.sqlalchemy_store import SQLAlchemyRefreshStore, refresh_tables

families, tokens = refresh_tables(Base.metadata)   # on your own metadata
auth = Auth(
    users=MyUsers(),                                # by_login / by_id -> AuthUser
    access=AccessTokens(settings.jwt_secret),
    refresh=RefreshTokens(SQLAlchemyRefreshStore(sessionmaker, families, tokens)),
)
app.include_router(auth_router(auth), prefix="/api/v1")
current_claims = bearer_claims(auth)                # a dependency
```

`python/examples/demo_app.py` is a complete, runnable one.

**React**:

```tsx
import { AuthProvider, tandemServer, useSession } from "tandem-auth";

<AuthProvider
  config={{
    server: tandemServer({ baseUrl: "https://api.example.org/api/v1" }),
    fetchMe: (token) => getMe(token), // your own endpoint
  }}
>
  <App />
</AuthProvider>;
```

Route guards for TanStack Router are in `tandem-auth/tanstack-router`. An
app's own HTTP client calls `requestTokenRefresh()` on a 401 and retries once.

## Development

```bash
cd python && uv run pytest && uv run ruff check .
cd js && pnpm test && pnpm run typecheck
cd js && pnpm test:e2e      # the JS client against the Python server
```
