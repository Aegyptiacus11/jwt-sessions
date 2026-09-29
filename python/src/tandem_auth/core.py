"""The session lifecycle: sign in, refresh, sign out - in terms of the two
things an application supplies, where its users are (`UserStore`) and where
refresh tokens are kept (`RefreshStore`).

Framework-free; `tandem_auth.fastapi` puts it behind HTTP.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from tandem_auth.passwords import check_password
from tandem_auth.refresh import RefreshRejected, RefreshTokens
from tandem_auth.tokens import AccessTokens


@dataclass(frozen=True)
class AuthUser:
    """What the library needs to know about a user."""

    id: str
    password_hash: str
    active: bool = True
    #: Extra claims for the access token - a role, say. Read again on every
    #: refresh, so a changed role reaches the token within one access TTL.
    claims: Mapping[str, Any] = field(default_factory=dict)


class UserStore(Protocol):
    async def by_login(self, login: str) -> AuthUser | None:
        """The user signing in as `login` (an email, usually). Normalise case
        here if logins are case-insensitive."""
        ...

    async def by_id(self, user_id: str) -> AuthUser | None: ...


class InvalidCredentials(Exception):
    """Wrong login or password, or an inactive account - deliberately one
    error, so the response does not say which."""


@dataclass(frozen=True)
class Session:
    access_token: str
    refresh_token: str
    user_id: str


@dataclass
class Auth:
    users: UserStore
    access: AccessTokens
    refresh: RefreshTokens

    async def login(
        self, login: str, password: str, *, now: datetime | None = None
    ) -> Session:
        user = await self.users.by_login(login)
        # Always one argon2 verification, account or not - see passwords.py.
        ok = check_password(password, user.password_hash if user else None)
        if user is None or not ok or not user.active:
            raise InvalidCredentials
        refresh_token = await self.refresh.start(user.id, now=now)
        return Session(
            access_token=self.access.issue(user.id, user.claims, now=now),
            refresh_token=refresh_token,
            user_id=user.id,
        )

    async def renew(
        self, refresh_token: str, *, now: datetime | None = None
    ) -> Session:
        """A new access token and the refresh token's successor; RefreshRejected
        otherwise. An account deactivated since sign-in ends the session."""
        rotated = await self.refresh.rotate(refresh_token, now=now)
        user = await self.users.by_id(rotated.user_id)
        if user is None or not user.active:
            await self.refresh.revoke(rotated.token, now=now)
            raise RefreshRejected("inactive")
        return Session(
            access_token=self.access.issue(user.id, user.claims, now=now),
            refresh_token=rotated.token,
            user_id=user.id,
        )

    async def logout(self, refresh_token: str, *, now: datetime | None = None) -> None:
        await self.refresh.revoke(refresh_token, now=now)

    async def logout_everywhere(
        self, user_id: str, *, now: datetime | None = None
    ) -> int:
        return await self.refresh.revoke_user(user_id, now=now)
