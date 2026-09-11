"""Python mirror of the authoritative Go scope engine.

The gateway uses this to (a) power the scope editor's "test a target" feature
and (b) pre-validate a scan's targets before enqueueing a job. The Go engine in
the orchestrator is authoritative for every outbound request at run time; both
implementations are verified against testdata/fixtures/scope_cases.json (see
tests/test_scope_parity.py).
"""

from app.scope.engine import Decision, Engine, Policy, Rule, Target, compile_policy

__all__ = ["Decision", "Engine", "Policy", "Rule", "Target", "compile_policy"]
