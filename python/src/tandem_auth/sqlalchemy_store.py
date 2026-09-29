"""A `RefreshStore` on SQLAlchemy (async), for any database it supports.

The tables are defined on the application's own `MetaData`, so its
migrations (Alembic autogenerate included) see them like any other table:

    families, tokens = refresh_tables(Base.metadata)
    store = SQLAlchemyRefreshStore(async_sessionmaker(engine), families, tokens)

`mark_used` is a conditional UPDATE (`... WHERE used_at IS NULL`), which is
what makes it atomic: of two concurrent refreshes with the same token,
exactly one changes a row.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    MetaData,
    String,
    Table,
    delete,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tandem_auth.refresh import RefreshRecord


def refresh_tables(metadata: MetaData, prefix: str = "tandem_") -> tuple[Table, Table]:
    families = Table(
        f"{prefix}refresh_families",
        metadata,
        Column("id", String(32), primary_key=True),
        Column("user_id", String(64), nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("revoked_at", DateTime(timezone=True), nullable=True),
        Index(f"ix_{prefix}refresh_families_user_id", "user_id"),
    )
    tokens = Table(
        f"{prefix}refresh_tokens",
        metadata,
        # SHA-256 of the token, hex. The token itself is never stored.
        Column("token_hash", String(64), primary_key=True),
        Column(
            "family_id",
            String(32),
            ForeignKey(families.c.id, ondelete="CASCADE"),
            nullable=False,
        ),
        Column("issued_at", DateTime(timezone=True), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("used_at", DateTime(timezone=True), nullable=True),
        Index(f"ix_{prefix}refresh_tokens_family_id", "family_id"),
        Index(f"ix_{prefix}refresh_tokens_expires_at", "expires_at"),
    )
    return families, tokens


def _aware(value: datetime | None) -> datetime | None:
    # SQLite hands timezone-aware columns back naive; they were written UTC.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class SQLAlchemyRefreshStore:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        families: Table,
        tokens: Table,
    ) -> None:
        self._sessions = sessions
        self._families = families
        self._tokens = tokens

    async def create_family(self, family_id: str, user_id: str, at: datetime) -> None:
        async with self._sessions.begin() as session:
            await session.execute(
                self._families.insert().values(
                    id=family_id, user_id=user_id, created_at=at
                )
            )

    async def add_token(
        self, token_hash: str, family_id: str, issued_at: datetime, expires_at: datetime
    ) -> None:
        async with self._sessions.begin() as session:
            await session.execute(
                self._tokens.insert().values(
                    token_hash=token_hash,
                    family_id=family_id,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
            )

    async def get(self, token_hash: str) -> RefreshRecord | None:
        t, f = self._tokens, self._families
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(
                        t.c.token_hash,
                        t.c.family_id,
                        f.c.user_id,
                        t.c.issued_at,
                        t.c.expires_at,
                        t.c.used_at,
                        f.c.revoked_at,
                    )
                    .join(f, f.c.id == t.c.family_id)
                    .where(t.c.token_hash == token_hash)
                )
            ).first()
        if row is None:
            return None
        return RefreshRecord(
            token_hash=row.token_hash,
            family_id=row.family_id,
            user_id=row.user_id,
            issued_at=_aware(row.issued_at),
            expires_at=_aware(row.expires_at),
            used_at=_aware(row.used_at),
            family_revoked_at=_aware(row.revoked_at),
        )

    async def mark_used(self, token_hash: str, at: datetime) -> bool:
        async with self._sessions.begin() as session:
            result = await session.execute(
                update(self._tokens)
                .where(
                    self._tokens.c.token_hash == token_hash,
                    self._tokens.c.used_at.is_(None),
                )
                .values(used_at=at)
            )
        return result.rowcount == 1

    async def revoke_family(self, family_id: str, at: datetime) -> None:
        async with self._sessions.begin() as session:
            await session.execute(
                update(self._families)
                .where(
                    self._families.c.id == family_id,
                    self._families.c.revoked_at.is_(None),
                )
                .values(revoked_at=at)
            )

    async def revoke_user(self, user_id: str, at: datetime) -> int:
        async with self._sessions.begin() as session:
            result = await session.execute(
                update(self._families)
                .where(
                    self._families.c.user_id == user_id,
                    self._families.c.revoked_at.is_(None),
                )
                .values(revoked_at=at)
            )
        return result.rowcount

    async def purge(self, before: datetime) -> int:
        async with self._sessions.begin() as session:
            result = await session.execute(
                delete(self._tokens).where(self._tokens.c.expires_at < before)
            )
        return result.rowcount
