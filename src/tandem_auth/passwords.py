"""Password hashing: argon2id through pwdlib, and a login check that takes
the same time whether or not the account exists.

The platform this was extracted from answered an unknown email without
hashing anything, so "no such account" came back measurably faster than
"wrong password" - which tells anyone timing the endpoint which addresses
have accounts. `check_password` always runs one argon2 verification.
"""

from __future__ import annotations

import secrets

from pwdlib import PasswordHash

_hasher = PasswordHash.recommended()

# Verified against when there is no account, so both paths cost one argon2
# verification. It matches no password anyone sends (it is the hash of a
# random value discarded at import).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def check_password(password: str, hashed: str | None) -> bool:
    """Whether `password` matches `hashed`; `hashed` is None when there is
    no such account, and the answer is then False after the same work."""
    if hashed is None:
        _hasher.verify(password, _DUMMY_HASH)
        return False
    return _hasher.verify(password, hashed)


def needs_rehash(hashed: str) -> bool:
    """True when `hashed` was made with weaker parameters than today's
    defaults - rehash it on the next successful login."""
    return _hasher.current_hasher.check_needs_rehash(hashed)
