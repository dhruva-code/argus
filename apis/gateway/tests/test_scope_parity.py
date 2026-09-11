"""The Python scope engine must agree with the Go engine on every shared
fixture (testdata/fixtures/scope_cases.json)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.scope import Target, compile_policy
from app.scope.engine import Policy, ScopePolicyError

FIXTURES = Path(__file__).resolve().parents[3] / "testdata" / "fixtures" / "scope_cases.json"


def _load():
    data = json.loads(FIXTURES.read_text())
    out = []
    for suite in data["suites"]:
        for i, case in enumerate(suite["cases"]):
            out.append((f"{suite['name']} #{i}", suite["policy"], case))
    return out


@pytest.mark.parametrize("name,policy,case", _load(), ids=lambda v: v if isinstance(v, str) else "")
def test_fixture_parity(name, policy, case):
    engine = compile_policy(policy)
    t = case["target"]
    decision = engine.evaluate(
        Target(
            host=t.get("host", ""),
            ip=t.get("ip", ""),
            port=t.get("port", 0),
            path=t.get("path", ""),
            asn=t.get("asn", ""),
        )
    )
    assert decision.allowed is (case["want"] == "allow"), f"{name}: {decision.reason}"
    want_rule = case["want_rule"]
    if want_rule is None:
        assert decision.rule_id == "", f"{name}: unexpected rule {decision.rule_id}"
    else:
        assert decision.rule_id == want_rule, f"{name}: got {decision.rule_id}"


def test_bad_policies_rejected():
    for bad in (
        {"rules": [{"id": "x", "effect": "allow", "type": "cidr", "value": "nope"}]},
        {"rules": [{"id": "x", "effect": "allow", "type": "regex", "value": "([a-z"}]},
        {"rules": [{"id": "x", "effect": "maybe", "type": "domain", "value": "example.com"}]},
        {"rules": [{"id": "x", "effect": "allow", "type": "bogus", "value": "example.com"}]},
    ):
        with pytest.raises(ScopePolicyError):
            compile_policy(Policy.from_dict(bad))
