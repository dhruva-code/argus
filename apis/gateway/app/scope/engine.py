"""Scope decision engine — see app/scope/__init__.py for the parity contract."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

_ALLOW = "allow"
_DENY = "deny"


@dataclass
class Rule:
    id: str
    effect: str
    type: str
    value: str
    ports: list[int] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Rule:
        return cls(
            id=str(d.get("id", "")),
            effect=str(d["effect"]),
            type=str(d["type"]),
            value=str(d.get("value", "")),
            ports=[int(p) for p in d.get("ports") or []],
            paths=list(d.get("paths") or []),
        )


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Policy:
        return cls(rules=[Rule.from_dict(r) for r in d.get("rules", [])])


@dataclass
class Target:
    host: str = ""
    ip: str = ""
    port: int = 0
    path: str = ""
    asn: str = ""


@dataclass
class Decision:
    allowed: bool
    rule_id: str
    reason: str


class ScopePolicyError(ValueError):
    """Raised when a policy fails to compile."""


def _norm_host(h: str) -> str:
    return h.strip().lower().rstrip(".")


def _norm_asn(a: str) -> str:
    return a.strip().upper().removeprefix("AS")


def _strip_scheme(u: str) -> str:
    if "://" in u:
        u = u.split("://", 1)[1]
    return u.rstrip("/")


def _anchor(rx: str) -> str:
    if not rx.startswith("^"):
        rx = "^" + rx
    if not rx.endswith("$"):
        rx = rx + "$"
    return rx


class Engine:
    _VALID = {"domain", "subdomain", "wildcard", "cidr", "ip", "asn", "url", "regex"}

    def __init__(self, policy: Policy):
        self._rules = policy.rules
        self._re: dict[str, re.Pattern[str]] = {}
        self._nets: dict[str, ipaddress._BaseNetwork] = {}
        for i, r in enumerate(policy.rules):
            if r.effect not in (_ALLOW, _DENY):
                raise ScopePolicyError(f"rule {i} ({r.id}): invalid effect {r.effect!r}")
            if r.type not in self._VALID:
                raise ScopePolicyError(f"rule {i} ({r.id}): unknown matcher type {r.type!r}")
            if r.type == "regex":
                try:
                    self._re[r.id] = re.compile(_anchor(r.value))
                except re.error as exc:
                    raise ScopePolicyError(f"rule {i} ({r.id}): bad regex: {exc}") from exc
            elif r.type == "cidr":
                try:
                    self._nets[r.id] = ipaddress.ip_network(r.value, strict=False)
                except ValueError as exc:
                    raise ScopePolicyError(f"rule {i} ({r.id}): bad CIDR: {exc}") from exc
            elif not r.value.strip():
                raise ScopePolicyError(f"rule {i} ({r.id}): empty value")

    def evaluate(self, target: Target) -> Decision:
        t = self._normalize(target)
        for r in self._rules:
            if r.effect == _DENY and self._matches(r, t):
                return Decision(False, r.id, f"matched deny rule {r.id}")
        for r in self._rules:
            if r.effect == _ALLOW and self._matches(r, t):
                return Decision(True, r.id, f"matched allow rule {r.id}")
        return Decision(False, "", "no allow rule matched (default deny)")

    # ── internals ──────────────────────────────────────────────────────────

    @staticmethod
    def _normalize(t: Target) -> Target:
        host = _norm_host(t.host)
        ip = t.ip
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                pass
        path = t.path
        if path and not path.startswith("/"):
            path = "/" + path
        return Target(host=host, ip=ip, port=t.port, path=path, asn=t.asn)

    def _matches(self, r: Rule, t: Target) -> bool:
        if r.ports:
            if not t.port or t.port not in r.ports:
                return False
        if r.paths:
            if not t.path or not any(t.path.startswith(p) for p in r.paths):
                return False
        return self._match_target(r, t)

    def _match_target(self, r: Rule, t: Target) -> bool:
        if r.type == "domain":
            return bool(t.host) and t.host == _norm_host(r.value)
        if r.type == "subdomain":
            v = _norm_host(r.value)
            return bool(t.host) and (t.host == v or t.host.endswith("." + v))
        if r.type == "wildcard":
            v = _norm_host(r.value)
            if v == "*":
                return bool(t.host)
            base = v[2:] if v.startswith("*.") else v
            return bool(t.host) and t.host.endswith("." + base) and t.host != base
        if r.type == "ip":
            return bool(t.ip) and self._ip_eq(t.ip, r.value)
        if r.type == "cidr":
            if not t.ip:
                return False
            try:
                return ipaddress.ip_address(t.ip) in self._nets[r.id]
            except ValueError:
                return False
        if r.type == "asn":
            return bool(t.asn) and _norm_asn(t.asn) == _norm_asn(r.value)
        if r.type == "regex":
            return bool(t.host) and self._re[r.id].match(t.host) is not None
        if r.type == "url":
            want = _strip_scheme(r.value)
            return bool(t.host) and (t.host + t.path).startswith(want)
        return False

    @staticmethod
    def _ip_eq(a: str, b: str) -> bool:
        try:
            return ipaddress.ip_address(a) == ipaddress.ip_address(b)
        except ValueError:
            return a == b


def compile_policy(data: dict[str, Any] | Policy) -> Engine:
    policy = data if isinstance(data, Policy) else Policy.from_dict(data)
    return Engine(policy)
