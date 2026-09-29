"""An in-memory `RefreshStore` - for tests and single-process demos. A
restart signs everyone out."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime

from jwt_sessions.refresh import RefreshRecord


@dataclass
class _Family:
    user_id: str
    revoked_at: datetime | None = None


class InMemoryRefreshStore:
    def __init__(self) -> None:
        self._families: dict[str, _Family] = {}
        self._tokens: dict[str, RefreshRecord] = {}
        self._lock = asyncio.Lock()

    async def create_family(self, family_id: str, user_id: str, at: datetime) -> None:
        self._families[family_id] = _Family(user_id=user_id)

    async def add_token(
        self, token_hash: str, family_id: str, issued_at: datetime, expires_at: datetime
    ) -> None:
        family = self._families[family_id]
        self._tokens[token_hash] = RefreshRecord(
            token_hash=token_hash,
            family_id=family_id,
            user_id=family.user_id,
            issued_at=issued_at,
            expires_at=expires_at,
            used_at=None,
            family_revoked_at=None,
        )

    async def get(self, token_hash: str) -> RefreshRecord | None:
        record = self._tokens.get(token_hash)
        if record is None:
            return None
        return replace(
            record, family_revoked_at=self._families[record.family_id].revoked_at
        )

    async def mark_used(self, token_hash: str, at: datetime) -> bool:
        async with self._lock:
            record = self._tokens.get(token_hash)
            if record is None or record.used_at is not None:
                return False
            self._tokens[token_hash] = replace(record, used_at=at)
            return True

    async def revoke_family(self, family_id: str, at: datetime) -> None:
        family = self._families.get(family_id)
        if family is not None and family.revoked_at is None:
            family.revoked_at = at

    async def revoke_user(self, user_id: str, at: datetime) -> int:
        live = [
            f
            for f in self._families.values()
            if f.user_id == user_id and f.revoked_at is None
        ]
        for family in live:
            family.revoked_at = at
        return len(live)

    async def purge(self, before: datetime) -> int:
        stale = [h for h, r in self._tokens.items() if r.expires_at < before]
        for h in stale:
            del self._tokens[h]
        return len(stale)
