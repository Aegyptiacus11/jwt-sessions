"""Access tokens: short-lived, stateless HS256 JWTs.

Stateless on purpose - checking one costs an HMAC, not a database read -
which is why they are short-lived (15 minutes by default): revoking a
session takes effect at the next refresh, and an access token outlives its
session by at most its own lifetime. Refresh tokens are the stateful half
(`refresh.py`).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt

ALGORITHM = "HS256"
#: Set by the library; an app's extra claims may not replace them.
RESERVED_CLAIMS = frozenset({"sub", "typ", "iat", "exp", "nbf", "jti", "iss", "aud"})


class InvalidToken(Exception):
    """Malformed, forged, expired, or not an access token."""


@dataclass(frozen=True)
class AccessTokens:
    secret: str
    ttl_seconds: int = 15 * 60
    issuer: str | None = None
    audience: str | None = None
    #: Clock skew tolerated when checking `exp` / `iat`, in seconds.
    leeway_seconds: int = 0

    def __post_init__(self) -> None:
        # RFC 7518 3.2: an HS256 key must be at least as long as the hash.
        if len(self.secret.encode()) < 32:
            raise ValueError("the signing secret must be at least 32 bytes")
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

    def issue(
        self,
        subject: str,
        claims: Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> str:
        extra = dict(claims or {})
        clash = RESERVED_CLAIMS.intersection(extra)
        if clash:
            raise ValueError(f"claims may not set {sorted(clash)}")
        now = now or datetime.now(UTC)
        payload: dict[str, Any] = {
            **extra,
            "sub": subject,
            "typ": "access",
            "iat": now,
            "exp": now + timedelta(seconds=self.ttl_seconds),
            "jti": uuid4().hex,
        }
        if self.issuer:
            payload["iss"] = self.issuer
        if self.audience:
            payload["aud"] = self.audience
        return jwt.encode(payload, self.secret, algorithm=ALGORITHM)

    def verify(self, token: str) -> dict[str, Any]:
        """The token's claims, or InvalidToken."""
        try:
            claims = jwt.decode(
                token,
                self.secret,
                # Pinned: the algorithm is never taken from the token.
                algorithms=[ALGORITHM],
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"require": ["sub", "typ", "iat", "exp"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(str(exc)) from exc
        if claims.get("typ") != "access":
            raise InvalidToken("not an access token")
        return claims
