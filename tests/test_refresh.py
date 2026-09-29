"""Rotation, reuse detection and revocation, against every store."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from jwt_sessions import RefreshRejected, RefreshTokens
from jwt_sessions.refresh import token_hash

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def later(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


async def test_rotation_spends_the_token_and_issues_a_successor(store):
    tokens = RefreshTokens(store, reuse_grace_seconds=0)
    first = await tokens.start("u1", now=T0)
    rotated = await tokens.rotate(first, now=later(60))
    assert rotated.user_id == "u1"
    assert rotated.token != first
    again = await tokens.rotate(rotated.token, now=later(120))
    assert again.family_id == rotated.family_id


async def test_a_replayed_token_revokes_the_whole_family(store):
    """The theft case: the attacker's copy and the user's live token both
    die, whichever of them is the thief."""
    tokens = RefreshTokens(store, reuse_grace_seconds=0)
    stolen = await tokens.start("u1", now=T0)
    legit = await tokens.rotate(stolen, now=later(60))  # the real user refreshes
    with pytest.raises(RefreshRejected) as replay:
        await tokens.rotate(stolen, now=later(120))  # the thief replays
    assert replay.value.reason == "reused"
    with pytest.raises(RefreshRejected) as after:
        await tokens.rotate(legit.token, now=later(180))
    assert after.value.reason == "revoked"


async def test_a_replay_within_the_grace_window_is_two_tabs_not_a_thief(store):
    tokens = RefreshTokens(store, reuse_grace_seconds=10)
    shared = await tokens.start("u1", now=T0)
    a = await tokens.rotate(shared, now=later(60))
    b = await tokens.rotate(shared, now=later(65))  # the second tab, 5 s later
    assert a.family_id == b.family_id
    await tokens.rotate(a.token, now=later(70))
    await tokens.rotate(b.token, now=later(70))
    with pytest.raises(RefreshRejected, match="reused"):
        await tokens.rotate(shared, now=later(80))  # 20 s on: not a race any more


async def test_concurrent_rotations_spend_a_token_once(store):
    """`mark_used` is atomic: with no grace, of two refreshes racing on one
    token exactly one succeeds - and the loser, a reuse, ends the family."""
    tokens = RefreshTokens(store, reuse_grace_seconds=0)
    token = await tokens.start("u1", now=T0)
    results = await asyncio.gather(
        tokens.rotate(token, now=later(1)),
        tokens.rotate(token, now=later(1)),
        return_exceptions=True,
    )
    assert sum(isinstance(r, RefreshRejected) for r in results) == 1


async def test_expired_unknown_and_logged_out(store):
    tokens = RefreshTokens(store, ttl_seconds=3600)
    token = await tokens.start("u1", now=T0)
    with pytest.raises(RefreshRejected, match="expired"):
        await tokens.rotate(token, now=later(3601))
    with pytest.raises(RefreshRejected, match="unknown"):
        await tokens.rotate("never-issued", now=T0)
    session = await tokens.start("u1", now=T0)
    await tokens.revoke(session, now=later(1))
    with pytest.raises(RefreshRejected, match="revoked"):
        await tokens.rotate(session, now=later(2))
    await tokens.revoke("never-issued")  # signing out twice is fine


async def test_revoke_user_ends_every_session_and_only_theirs(store):
    tokens = RefreshTokens(store)
    phone = await tokens.start("u1", now=T0)
    laptop = await tokens.start("u1", now=T0)
    other = await tokens.start("u2", now=T0)
    assert await tokens.revoke_user("u1", now=later(1)) == 2
    for token in (phone, laptop):
        with pytest.raises(RefreshRejected, match="revoked"):
            await tokens.rotate(token, now=later(2))
    await tokens.rotate(other, now=later(2))


async def test_only_a_hash_is_stored_and_expired_tokens_purge(store):
    tokens = RefreshTokens(store, ttl_seconds=60)
    token = await tokens.start("u1", now=T0)
    assert await store.get(token) is None
    assert (await store.get(token_hash(token))) is not None
    assert await store.purge(later(61)) == 1
    assert await store.get(token_hash(token)) is None
