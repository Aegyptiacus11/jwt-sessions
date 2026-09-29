"""The smallest application using tandem-auth.

    uv run uvicorn examples.demo_app:app --port 8000

One user, ada@example.com / correct-horse, kept in memory. A real
application keeps users in its database (`UserStore`) and refresh tokens in
it too (`SQLAlchemyRefreshStore`).
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, FastAPI

from tandem_auth import (
    AccessTokens,
    Auth,
    AuthUser,
    InMemoryRefreshStore,
    RefreshTokens,
    hash_password,
)
from tandem_auth.fastapi import CookieSettings, auth_router, bearer_claims

USERS = {
    "ada@example.com": AuthUser(
        id="u-ada",
        password_hash=hash_password("correct-horse"),
        claims={"role": "admin"},
    )
}


class Users:
    async def by_login(self, login: str) -> AuthUser | None:
        return USERS.get(login.strip().lower())

    async def by_id(self, user_id: str) -> AuthUser | None:
        return next((u for u in USERS.values() if u.id == user_id), None)


auth = Auth(
    users=Users(),
    access=AccessTokens(
        os.environ.get("DEMO_SECRET", "demo-secret-only-for-the-demo-app-000000")
    ),
    refresh=RefreshTokens(
        InMemoryRefreshStore(),
        reuse_grace_seconds=int(os.environ.get("DEMO_REUSE_GRACE", "10")),
    ),
)
current = bearer_claims(auth)

app = FastAPI(title="tandem-auth demo")
# Plain HTTP on localhost: a Secure cookie would never be sent back.
app.include_router(
    auth_router(auth, cookie=CookieSettings(secure=False)), prefix="/api"
)


@app.get("/api/me")
async def me(claims: dict[str, Any] = Depends(current)) -> dict[str, Any]:
    user = await Users().by_id(claims["sub"])
    return {
        "id": claims["sub"],
        "email": next(k for k, v in USERS.items() if v is user),
        "roles": [claims["role"]],
    }
