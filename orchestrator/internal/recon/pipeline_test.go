package recon

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/argus-platform/orchestrator/internal/scope"
	"github.com/argus-platform/orchestrator/internal/ssrf"
)

func testEngine(t *testing.T) (*scope.Engine, *ssrf.Guard) {
	t.Helper()
	eng, err := scope.Compile(scope.Policy{Rules: []scope.Rule{
		{ID: "a1", Effect: scope.Allow, Type: scope.MatchSubdomain, Value: "example.com"},
		{ID: "d1", Effect: scope.Deny, Type: scope.MatchDomain, Value: "admin.example.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := ssrf.NewGuard(nil, true)
	return eng, g
}

func collect(t *testing.T, phases []string) ([]Asset, []Edge, Result) {
	t.Helper()
	t.Setenv("ARGUS_SYNTHETIC_RECON", "true")
	eng, guard := testEngine(t)
	var assets []Asset
	var edges []Edge
	cb := Callbacks{
		Log:        func(_, _ string) {},
		Asset:      func(a Asset) { assets = append(assets, a) },
		Edge:       func(e Edge) { edges = append(edges, e) },
		Checkpoint: func(_ string, _ map[string]any) {},
		Cancelled:  func() bool { return false },
	}
	res, err := Run(context.Background(), eng, guard, nil, Options{
		Roots: []string{"example.com"}, Phases: phases, MaxTargets: 100,
	}, cb)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return assets, edges, res
}

func TestSyntheticFullPipeline(t *testing.T) {
	assets, edges, res := collect(t, []string{PhasePassiveEnum, PhaseActiveEnum, PhaseMergeAlive})

	if res.Discovered < 5 {
		t.Errorf("expected >=5 discovered, got %d", res.Discovered)
	}
	if res.Resolved == 0 || res.Alive == 0 {
		t.Errorf("expected resolution + alive hosts, got resolved=%d alive=%d", res.Resolved, res.Alive)
	}
	if len(edges) == 0 {
		t.Error("expected edges (resolves_to / hosts)")
	}

	var sawInScope, sawOutOfScope, sawAlive, sawIP bool
	for _, a := range assets {
		if a.Value == "www.example.com" {
			sawInScope = true
		}
		if strings.Contains(a.Value, "cdn-partner.test") && !a.InScope {
			sawOutOfScope = true
		}
		if a.Status == StatusAlive {
			sawAlive = true
		}
		if a.Type == TypeIP {
			sawIP = true
			if !strings.HasPrefix(a.Value, "203.0.113.") {
				t.Errorf("synthetic IP outside TEST-NET-3: %s", a.Value)
			}
		}
	}
	if !sawInScope || !sawOutOfScope || !sawAlive || !sawIP {
		t.Errorf("coverage: inScope=%v outOfScope=%v alive=%v ip=%v",
			sawInScope, sawOutOfScope, sawAlive, sawIP)
	}
}

func TestDenyRuleHostNeverProbed(t *testing.T) {
	assets, _, _ := collect(t, []string{PhasePassiveEnum, PhaseActiveEnum, PhaseMergeAlive})
	for _, a := range assets {
		if a.Value == "admin.example.com" && a.Status == StatusAlive {
			t.Fatal("admin.example.com is denied by scope but was probed alive")
		}
	}
}

func TestPassiveOnlyDoesNotResolve(t *testing.T) {
	assets, _, res := collect(t, []string{PhasePassiveEnum})
	if res.Resolved != 0 || res.Alive != 0 {
		t.Errorf("passive-only should not resolve/probe: %+v", res)
	}
	for _, a := range assets {
		if a.Status == StatusResolved || a.Status == StatusAlive {
			t.Errorf("passive-only emitted %s for %s", a.Status, a.Value)
		}
	}
}

func TestSyntheticIsDeterministic(t *testing.T) {
	a1, _, _ := collect(t, []string{PhasePassiveEnum, PhaseActiveEnum, PhaseMergeAlive})
	a2, _, _ := collect(t, []string{PhasePassiveEnum, PhaseActiveEnum, PhaseMergeAlive})
	if len(a1) != len(a2) {
		t.Errorf("non-deterministic: %d vs %d assets", len(a1), len(a2))
	}
}

func TestNoRootsIsCallerError(t *testing.T) {
	// Run itself tolerates empty roots (returns empty); the engine handler is
	// what rejects. Just make sure it doesn't panic.
	_ = os.Setenv("ARGUS_SYNTHETIC_RECON", "true")
	defer os.Unsetenv("ARGUS_SYNTHETIC_RECON")
	eng, guard := testEngine(t)
	_, err := Run(context.Background(), eng, guard, nil,
		Options{Roots: nil, Phases: []string{PhasePassiveEnum}}, Callbacks{
			Log: func(_, _ string) {}, Asset: func(Asset) {}, Edge: func(Edge) {},
			Checkpoint: func(string, map[string]any) {}, Cancelled: func() bool { return false },
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
