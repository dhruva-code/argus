from app.core import security
from app.core.crypto import decrypt, encrypt, mask


def test_password_roundtrip():
    h = security.hash_password("correct horse battery staple")
    assert security.verify_password("correct horse battery staple", h)
    assert not security.verify_password("wrong", h)


def test_jwt_roundtrip_and_kind_enforced():
    tok, _ = security.create_token("user-1", "access")
    payload = security.decode_token(tok, expected_kind="access")
    assert payload["sub"] == "user-1"
    try:
        security.decode_token(tok, expected_kind="refresh")
        raise AssertionError("should have rejected wrong kind")
    except ValueError:
        pass


def test_secret_encryption_roundtrip():
    enc = encrypt("sk-abc123")
    assert enc != "sk-abc123"
    assert decrypt(enc) == "sk-abc123"


def test_mask():
    assert mask("AKIAABCDEFGH") == "AKIA********"
    assert mask("xy") == "**"


def test_totp():
    secret = security.new_mfa_secret()
    import pyotp

    code = pyotp.TOTP(secret).now()
    assert security.verify_mfa(secret, code)
    assert not security.verify_mfa(secret, "000000")
