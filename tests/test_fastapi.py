"""The HTTP contract, end to end: a FastAPI app mounting the router under a
prefix, as an application would, and a client holding the cookie."""

from dataclasses import dataclass, field

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from jwt_sessions import (
    AccessTokens,
    Auth,
    AuthUser,
    InMemoryRefreshStore,
    RefreshTokens,
    hash_password,
)
from jwt_sessions.fastapi import CookieSettings, auth_router, bearer_claims
from tests.conftest import SECRET


@dataclass
class Users:
    by_email: dict[str, AuthUser] = field(default_factory=dict)

    async def by_login(self, login: str) -> AuthUser | None:
        return self.by_email.get(login.lower())

    async def by_id(self, user_id: str) -> AuthUser | None:
        return next((u for u in self.by_email.values() if u.id == user_id), None)


@pytest.fixture
def users() -> Users:
    return Users(
        {
            "ada@example.com": AuthUser(
                id="u1", password_hash=hash_password("pw-ada"), claims={"role": "admin"}
            )
        }
    )


@pytest.fixture
async def client(users):
    auth = Auth(
        users=users,
        access=AccessTokens(SECRET),
        refresh=RefreshTokens(InMemoryRefreshStore(), reuse_grace_seconds=0),
    )
    app = FastAPI()
    # Plain HTTP in the test client, so the cookie cannot be Secure here.
    app.include_router(
        auth_router(auth, cookie=CookieSettings(secure=False)), prefix="/api/v1"
    )

    current_claims = bearer_claims(auth)

    @app.get("/api/v1/whoami")
    async def whoami(claims: dict = Depends(current_claims)) -> dict:
        return {"sub": claims["sub"], "role": claims["role"]}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


async def refresh_as(client: AsyncClient, token: str):
    """Refresh holding exactly this cookie - someone else's copy, say."""
    client.cookies.clear()
    client.cookies.set("refresh_token", token, path="/api/v1/auth")
    return await client.post("/api/v1/auth/refresh")


async def login(client: AsyncClient) -> str:
    response = await client.post(
        "/api/v1/auth/login", json={"email": "Ada@example.com", "password": "pw-ada"}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


async def test_login_sets_a_scoped_httponly_cookie_and_returns_only_the_access_token(
    client,
):
    response = await client.post(
        "/api/v1/auth/login", json={"email": "ada@example.com", "password": "pw-ada"}
    )
    body = response.json()
    assert set(body) == {"access_token", "token_type"}
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "Path=/api/v1/auth" in cookie  # only the auth endpoints get it
    assert "SameSite=lax" in cookie
    me = await client.get(
        "/api/v1/whoami", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.json() == {"sub": "u1", "role": "admin"}


async def test_unknown_email_and_wrong_password_look_the_same(client):
    a = await client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x"}
    )
    b = await client.post(
        "/api/v1/auth/login", json={"email": "ada@example.com", "password": "x"}
    )
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


async def test_refresh_rotates_the_cookie_and_a_replay_ends_the_session(client):
    await login(client)
    stolen = client.cookies.get("refresh_token")
    refreshed = await client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    current = client.cookies.get("refresh_token")
    assert current and current != stolen

    # Someone presents the old cookie: rejected, and the session is gone -
    # the real user's current cookie with it.
    replay = await refresh_as(client, stolen)
    assert replay.status_code == 401
    assert "Max-Age=0" in replay.headers["set-cookie"]
    assert (await refresh_as(client, current)).status_code == 401


async def test_logout_revokes_the_session_not_just_the_cookie(client):
    await login(client)
    kept = client.cookies.get("refresh_token")
    out = await client.post("/api/v1/auth/logout")
    assert out.status_code == 204
    # A copy of the cookie taken before signing out is worthless after.
    again = await refresh_as(client, kept)
    assert again.status_code == 401


async def test_logout_all_ends_every_session(client):
    access = await login(client)
    first = client.cookies.get("refresh_token")
    client.cookies.clear()
    await login(client)  # a second device
    out = await client.post(
        "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {access}"}
    )
    assert out.status_code == 204
    for cookie in (first, client.cookies.get("refresh_token")):
        r = await refresh_as(client, cookie)
        assert r.status_code == 401


async def test_a_deactivated_account_cannot_refresh(client, users):
    await login(client)
    old = users.by_email["ada@example.com"]
    users.by_email["ada@example.com"] = AuthUser(
        id=old.id, password_hash=old.password_hash, active=False
    )
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401
    relogin = await client.post(
        "/api/v1/auth/login", json={"email": "ada@example.com", "password": "pw-ada"}
    )
    assert relogin.status_code == 401


async def test_no_or_bad_bearer_is_401_with_a_challenge(client):
    for headers in ({}, {"Authorization": "Bearer nonsense"}):
        r = await client.get("/api/v1/whoami", headers=headers)
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == "Bearer"


async def test_an_oversized_password_is_refused_before_hashing(client):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "x" * 5000},
    )
    assert r.status_code == 422
