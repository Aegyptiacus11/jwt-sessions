from datetime import UTC, datetime, timedelta

import jwt
import pytest

from jwt_sessions import AccessTokens, InvalidToken
from tests.conftest import SECRET


def test_round_trip_carries_the_claims():
    tokens = AccessTokens(SECRET)
    claims = tokens.verify(tokens.issue("user-1", {"role": "admin"}))
    assert (claims["sub"], claims["role"], claims["typ"]) == (
        "user-1",
        "admin",
        "access",
    )


def test_expired_forged_and_foreign_tokens_are_refused():
    tokens = AccessTokens(SECRET, ttl_seconds=60)
    old = tokens.issue("u", now=datetime.now(UTC) - timedelta(minutes=5))
    with pytest.raises(InvalidToken):
        tokens.verify(old)
    other = AccessTokens("another-secret-also-long-enough-for-hs256")
    with pytest.raises(InvalidToken):
        tokens.verify(other.issue("u"))
    # Not an access token: right key, wrong type.
    refresh_like = jwt.encode(
        {
            "sub": "u",
            "typ": "refresh",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        SECRET,
        algorithm="HS256",
    )
    with pytest.raises(InvalidToken, match="not an access token"):
        tokens.verify(refresh_like)


def test_the_algorithm_is_never_taken_from_the_token():
    unsigned = jwt.encode(
        {
            "sub": "u",
            "typ": "access",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        key=None,
        algorithm="none",
    )
    with pytest.raises(InvalidToken):
        AccessTokens(SECRET).verify(unsigned)


def test_a_short_secret_and_reserved_claims_are_refused():
    with pytest.raises(ValueError, match="32 bytes"):
        AccessTokens("short")
    with pytest.raises(ValueError, match="sub"):
        AccessTokens(SECRET).issue("u", {"sub": "someone-else"})


def test_issuer_and_audience_are_checked_when_set():
    tokens = AccessTokens(SECRET, issuer="https://a.example", audience="api")
    assert tokens.verify(tokens.issue("u"))["aud"] == "api"
    elsewhere = AccessTokens(SECRET, issuer="https://b.example", audience="api")
    with pytest.raises(InvalidToken):
        tokens.verify(elsewhere.issue("u"))
