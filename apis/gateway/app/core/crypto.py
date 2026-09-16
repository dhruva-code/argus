"""Symmetric encryption for secrets stored at rest (tool API keys, detected
credentials).

Two backends (M7):

* **local (default)** — Fernet with a key from ``SECRET_ENCRYPTION_KEY`` (or,
  in development, derived from the JWT secret).
* **HashiCorp Vault Transit** — set ``VAULT_ADDR``, ``VAULT_TOKEN`` and
  ``VAULT_TRANSIT_KEY``; the plaintext never leaves Vault's control and the key
  can be rotated centrally. Ciphertext is stored with a ``vault:`` prefix so a
  later switch back to local still decrypts old local rows.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

_VAULT_PREFIX = "vault:"


@functools.lru_cache(maxsize=1)
def _vault_client():
    addr = os.getenv("VAULT_ADDR")
    key = os.getenv("VAULT_TRANSIT_KEY")
    if not addr or not key:
        return None
    try:
        import hvac  # noqa: PLC0415
    except ImportError:
        return None
    client = hvac.Client(url=addr, token=os.getenv("VAULT_TOKEN", ""))
    if not client.is_authenticated():
        return None
    return (client, key, os.getenv("VAULT_TRANSIT_MOUNT", "transit"))


def _fernet() -> Fernet:
    key = settings.secret_encryption_key.strip()
    if not key:
        derived = hashlib.sha256(settings.jwt_secret.encode()).digest()
        key = base64.urlsafe_b64encode(derived).decode()
    else:
        # Accept either a raw Fernet key or arbitrary text (hash to 32 bytes).
        try:
            base64.urlsafe_b64decode(key)
            if len(base64.urlsafe_b64decode(key)) != 32:
                raise ValueError
        except ValueError:
            key = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode()
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    v = _vault_client()
    if v is not None:
        client, key, mount = v
        b64 = base64.b64encode(plaintext.encode()).decode()
        resp = client.secrets.transit.encrypt_data(name=key, plaintext=b64, mount_point=mount)
        return _VAULT_PREFIX + resp["data"]["ciphertext"]
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    if token.startswith(_VAULT_PREFIX):
        v = _vault_client()
        if v is None:
            raise ValueError("ciphertext was written by Vault Transit but Vault is not configured")
        client, key, mount = v
        resp = client.secrets.transit.decrypt_data(
            name=key, ciphertext=token[len(_VAULT_PREFIX) :], mount_point=mount
        )
        return base64.b64decode(resp["data"]["plaintext"]).decode()
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:  # noqa: TRY003
        raise ValueError("could not decrypt stored secret (key rotated?)") from exc


def backend_name() -> str:
    return "vault-transit" if _vault_client() is not None else "local-fernet"


def mask(secret: str, keep: int = 4) -> str:
    if not secret:
        return ""
    if len(secret) <= keep:
        return "*" * len(secret)
    return secret[:keep] + "*" * (len(secret) - keep)
