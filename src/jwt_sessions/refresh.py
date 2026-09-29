"""Refresh tokens: opaque, rotated on every use, and grouped into families
so that a stolen one gives itself away.

A login starts a **family**. Every refresh spends the presented token and
issues its successor in the same family. A token presented a second time
means two parties hold it - the user and whoever copied it - and there is
no telling which is which, so the whole family is revoked: both are signed
out, and the thief's copy is dead. (A stateless refresh JWT, which is what
this replaces, cannot do any of that: a copied one keeps working until it
expires, however often the real user refreshes.)

One exception, `reuse_grace_seconds`: two tabs of the same browser that
refresh at the same moment both send the token the cookie held, and the
second arrives already spent. Within the grace window a spent token gets a
successor instead of revoking the family. It is a window a thief could use
too, if they replay within those seconds of the real refresh; the default
is 10 s, and 0 turns it off.

Tokens are random, not JWTs, and only their SHA-256 is stored, so a leaked
table holds nothing that can be presented.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class RefreshRecord:
    """One refresh token as stored, with its family's state."""

    token_hash: str
    family_id: str
    user_id: str
    issued_at: datetime
    expires_at: datetime
    used_at: datetime | None
    #: When the family was revoked - logout, reuse, or revoke-all.
    family_revoked_at: datetime | None


class RefreshStore(Protocol):
    """Where families and tokens live. `mark_used` must be atomic: of two
    concurrent calls for the same token, exactly one returns True."""

    async def create_family(
        self, family_id: str, user_id: str, at: datetime
    ) -> None: ...

    async def add_token(
        self, token_hash: str, family_id: str, issued_at: datetime, expires_at: datetime
    ) -> None: ...

    async def get(self, token_hash: str) -> RefreshRecord | None: ...

    async def mark_used(self, token_hash: str, at: datetime) -> bool: ...

    async def revoke_family(self, family_id: str, at: datetime) -> None: ...

    async def revoke_user(self, user_id: str, at: datetime) -> int:
        """Revoke every live family of the user; how many there were."""
        ...

    async def purge(self, before: datetime) -> int:
        """Drop tokens that expired before `before`; how many."""
        ...


class RefreshRejected(Exception):
    """The refresh token cannot be used. `reason` is one of "unknown",
    "expired", "revoked" and "reused" - for logs; a client is told only
    that it must sign in again."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Rotated:
    token: str
    user_id: str
    family_id: str


@dataclass
class RefreshTokens:
    store: RefreshStore
    ttl_seconds: int = 30 * 24 * 3600
    reuse_grace_seconds: int = 10

    async def start(self, user_id: str, *, now: datetime | None = None) -> str:
        """A new family for a fresh login, and its first token."""
        now = now or datetime.now(UTC)
        family_id = uuid4().hex
        await self.store.create_family(family_id, user_id, now)
        return await self._issue(family_id, now)

    async def rotate(self, token: str, *, now: datetime | None = None) -> Rotated:
        """Spend `token` and return its successor - or RefreshRejected, having
        revoked the family if the token had already been spent."""
        now = now or datetime.now(UTC)
        record = await self.store.get(token_hash(token))
        if record is None:
            raise RefreshRejected("unknown")
        if record.family_revoked_at is not None:
            raise RefreshRejected("revoked")
        if record.expires_at <= now:
            raise RefreshRejected("expired")
        if not await self.store.mark_used(record.token_hash, now):
            spent = await self.store.get(record.token_hash)
            used_at = spent.used_at if spent else None
            within_grace = (
                used_at is not None
                and self.reuse_grace_seconds > 0
                and now - used_at <= timedelta(seconds=self.reuse_grace_seconds)
            )
            if not within_grace:
                await self.store.revoke_family(record.family_id, now)
                raise RefreshRejected("reused")
        successor = await self._issue(record.family_id, now)
        return Rotated(
            token=successor, user_id=record.user_id, family_id=record.family_id
        )

    async def revoke(self, token: str, *, now: datetime | None = None) -> None:
        """End the session `token` belongs to (sign-out). Unknown tokens are
        ignored: signing out twice is not an error."""
        record = await self.store.get(token_hash(token))
        if record is not None:
            await self.store.revoke_family(record.family_id, now or datetime.now(UTC))

    async def revoke_user(self, user_id: str, *, now: datetime | None = None) -> int:
        """End every session of the user - sign out everywhere, a password
        change, a deactivated account."""
        return await self.store.revoke_user(user_id, now or datetime.now(UTC))

    async def _issue(self, family_id: str, now: datetime) -> str:
        token = secrets.token_urlsafe(32)
        await self.store.add_token(
            token_hash(token), family_id, now, now + timedelta(seconds=self.ttl_seconds)
        )
        return token
