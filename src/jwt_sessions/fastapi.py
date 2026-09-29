"""The HTTP contract, for FastAPI.

    POST {prefix}/login       {"email", "password"} -> {"access_token"}
                              + Set-Cookie: the refresh token (httpOnly)
    POST {prefix}/refresh     cookie -> {"access_token"} + the rotated cookie
    POST {prefix}/logout      cookie -> 204; session revoked, cookie cleared
    POST {prefix}/logout-all  Bearer -> 204; every session of the user revoked

The refresh token only ever travels in an httpOnly cookie - never in a body
JavaScript can read - and the access token only in response bodies and the
Authorization header, never in a cookie, so no request is authorised by a
cookie alone. The refresh cookie is SameSite=Lax by default: a cross-site
POST does not carry it, and nothing a cross-site page could make the
browser send gets it an access token it could read.

What a browser client has to do is in the README ("What a client has to
do"); there is no client library.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from jwt_sessions.core import Auth, InvalidCredentials
from jwt_sessions.refresh import RefreshRejected
from jwt_sessions.tokens import InvalidToken


@dataclass(frozen=True)
class CookieSettings:
    name: str = "refresh_token"
    #: None: the directory the auth endpoints are served from, worked out
    #: per request, so the cookie goes only to them wherever the router is
    #: mounted. Set it when the app sits behind a proxy that rewrites paths.
    path: str | None = None
    #: Off only for local development over plain HTTP.
    secure: bool = True
    samesite: Literal["lax", "strict", "none"] = "lax"
    domain: str | None = None


class LoginBody(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    # Bounded: argon2 hashes whatever it is given, and a megabyte password
    # is a cheap way to make a server do expensive work.
    password: str = Field(min_length=1, max_length=1024)


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - a scheme name


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def bearer_claims(auth: Auth) -> Callable[..., Awaitable[dict[str, Any]]]:
    """A dependency: the verified claims of the request's access token, or
    401. Loading the application's own user from `claims["sub"]` - and
    checking it is still allowed in - is the application's business."""
    scheme = HTTPBearer(auto_error=False)

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(scheme),
    ) -> dict[str, Any]:
        if credentials is None:
            raise _unauthorized("Not authenticated")
        try:
            return auth.access.verify(credentials.credentials)
        except InvalidToken as exc:
            raise _unauthorized("Invalid or expired access token") from exc

    return dependency


def auth_router(
    auth: Auth,
    *,
    cookie: CookieSettings | None = None,
    prefix: str = "/auth",
) -> APIRouter:
    cookie = cookie or CookieSettings()
    router = APIRouter(prefix=prefix, tags=["auth"])
    current_claims = bearer_claims(auth)

    def cookie_path(request: Request) -> str:
        if cookie.path is not None:
            return cookie.path
        return request.url.path.rsplit("/", 1)[0] or "/"

    def set_cookie(request: Request, response: Response, token: str) -> None:
        response.set_cookie(
            key=cookie.name,
            value=token,
            max_age=auth.refresh.ttl_seconds,
            path=cookie_path(request),
            domain=cookie.domain,
            secure=cookie.secure,
            httponly=True,
            samesite=cookie.samesite,
        )

    def clear_cookie(request: Request, response: Response) -> None:
        response.delete_cookie(
            key=cookie.name,
            path=cookie_path(request),
            domain=cookie.domain,
            secure=cookie.secure,
            httponly=True,
            samesite=cookie.samesite,
        )

    @router.post("/login", response_model=AccessTokenResponse)
    async def login(
        body: LoginBody, request: Request, response: Response
    ) -> AccessTokenResponse:
        try:
            session = await auth.login(body.email, body.password)
        except InvalidCredentials as exc:
            raise _unauthorized("Invalid email or password") from exc
        set_cookie(request, response, session.refresh_token)
        return AccessTokenResponse(access_token=session.access_token)

    @router.post("/refresh", response_model=AccessTokenResponse)
    async def refresh(request: Request, response: Response) -> AccessTokenResponse:
        token = request.cookies.get(cookie.name)
        if not token:
            raise _unauthorized("Missing refresh token")
        try:
            session = await auth.renew(token)
        except RefreshRejected as exc:
            # The cookie is dead either way; a 401 carries no Set-Cookie
            # unless it is attached to the exception.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired - sign in again",
                headers={
                    "WWW-Authenticate": "Bearer",
                    "Set-Cookie": _expired_cookie_header(cookie, cookie_path(request)),
                },
            ) from exc
        set_cookie(request, response, session.refresh_token)
        return AccessTokenResponse(access_token=session.access_token)

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(request: Request, response: Response) -> None:
        token = request.cookies.get(cookie.name)
        if token:
            await auth.logout(token)
        clear_cookie(request, response)

    @router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
    async def logout_all(
        request: Request,
        response: Response,
        claims: dict[str, Any] = Depends(current_claims),
    ) -> None:
        await auth.logout_everywhere(str(claims["sub"]))
        clear_cookie(request, response)

    return router


def _expired_cookie_header(cookie: CookieSettings, path: str) -> str:
    parts = [
        f'{cookie.name}=""',
        "Max-Age=0",
        f"Path={path}",
        "HttpOnly",
        f"SameSite={cookie.samesite}",
    ]
    if cookie.secure:
        parts.append("Secure")
    if cookie.domain:
        parts.append(f"Domain={cookie.domain}")
    return "; ".join(parts)
