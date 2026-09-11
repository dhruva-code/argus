"""Minimal dependency-free HTTP client and local credential store."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("ARGUS_CONFIG_DIR", Path.home() / ".config" / "argus"))
CONFIG_FILE = CONFIG_DIR / "config.json"


class ArgusError(RuntimeError):
    pass


def _load() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _save(cfg: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)


class Client:
    def __init__(self) -> None:
        self.cfg = _load()
        self.base = os.environ.get("ARGUS_API", self.cfg.get("api", "http://localhost:8000")).rstrip(
            "/"
        )

    # ── auth ──────────────────────────────────────────────────────────────
    def login(self, email: str, password: str, mfa: str | None = None) -> None:
        body: dict[str, Any] = {"email": email, "password": password}
        if mfa:
            body["mfa_code"] = mfa
        data = self._raw("POST", "/api/auth/login", body)
        self.cfg.update(
            api=self.base, access=data["access_token"], refresh=data["refresh_token"], email=email
        )
        _save(self.cfg)

    def use_org(self, org_id: str) -> None:
        self.cfg["org"] = org_id
        _save(self.cfg)

    def logout(self) -> None:
        for k in ("access", "refresh", "org"):
            self.cfg.pop(k, None)
        _save(self.cfg)

    # ── request plumbing ─────────────────────────────────────────────────
    def _raw(self, method: str, path: str, body: Any | None = None) -> Any:
        url = self.base + path
        headers = {"content-type": "application/json"}
        token = self.cfg.get("access")
        if token:
            headers["authorization"] = f"Bearer {token}"
        if self.cfg.get("org"):
            headers["x-org-id"] = self.cfg["org"]
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:  # noqa: S310
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            try:
                detail = json.loads(detail).get("detail", detail)
            except ValueError:
                pass
            raise ArgusError(f"{exc.code} {method} {path}: {detail}") from None
        except urllib.error.URLError as exc:
            raise ArgusError(f"cannot reach {self.base}: {exc.reason}") from None

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        try:
            return self._raw(method, path, body)
        except ArgusError as exc:
            if "401" in str(exc) and self.cfg.get("refresh"):
                data = self._raw(
                    "POST", "/api/auth/refresh", {"refresh_token": self.cfg["refresh"]}
                )
                self.cfg.update(access=data["access_token"], refresh=data["refresh_token"])
                _save(self.cfg)
                return self._raw(method, path, body)
            raise

    get = lambda self, p: self.request("GET", p)  # noqa: E731
    post = lambda self, p, b=None: self.request("POST", p, b)  # noqa: E731
    patch = lambda self, p, b=None: self.request("PATCH", p, b)  # noqa: E731
