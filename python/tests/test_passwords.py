from tandem_auth import check_password, hash_password, passwords


def test_check_password():
    hashed = hash_password("correct horse")
    assert check_password("correct horse", hashed)
    assert not check_password("wrong", hashed)


def test_no_account_costs_one_verification_too(monkeypatch):
    """An unknown login must not answer faster than a wrong password: both
    run exactly one argon2 verification."""
    calls = []
    real = passwords._hasher.verify
    monkeypatch.setattr(
        passwords._hasher, "verify", lambda pw, h: calls.append(h) or real(pw, h)
    )
    assert not check_password("anything", None)
    assert not check_password("anything", hash_password("other"))
    assert len(calls) == 2
    assert calls[0] == passwords._DUMMY_HASH
