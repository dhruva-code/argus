package scope

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixtureFile struct {
	Suites []struct {
		Name   string `json:"name"`
		Policy Policy `json:"policy"`
		Cases  []struct {
			Target   Target  `json:"target"`
			Want     string  `json:"want"`
			WantRule *string `json:"want_rule"`
		} `json:"cases"`
	} `json:"suites"`
}

func loadFixtures(t *testing.T) fixtureFile {
	t.Helper()
	// testdata/fixtures/scope_cases.json lives at the repo root.
	path := filepath.Join("..", "..", "..", "testdata", "fixtures", "scope_cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var ff fixtureFile
	if err := json.Unmarshal(raw, &ff); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	return ff
}

func TestFixtureParity(t *testing.T) {
	ff := loadFixtures(t)
	for _, suite := range ff.Suites {
		suite := suite
		t.Run(suite.Name, func(t *testing.T) {
			eng, err := Compile(suite.Policy)
			if err != nil {
				t.Fatalf("compile policy: %v", err)
			}
			for i, c := range suite.Cases {
				got := eng.Evaluate(c.Target)
				wantAllowed := c.Want == "allow"
				if got.Allowed != wantAllowed {
					t.Errorf("case %d %+v: allowed=%v want=%v (%s)", i, c.Target, got.Allowed, wantAllowed, got.Reason)
				}
				if c.WantRule != nil && got.RuleID != *c.WantRule {
					t.Errorf("case %d %+v: rule=%q want=%q", i, c.Target, got.RuleID, *c.WantRule)
				}
				if c.WantRule == nil && got.RuleID != "" {
					t.Errorf("case %d %+v: rule=%q want empty", i, c.Target, got.RuleID)
				}
			}
		})
	}
}

func TestCompileRejectsBadPolicy(t *testing.T) {
	cases := []Policy{
		{Rules: []Rule{{ID: "x", Effect: Allow, Type: MatchCIDR, Value: "not-a-cidr"}}},
		{Rules: []Rule{{ID: "x", Effect: Allow, Type: MatchRegex, Value: "([a-z"}}},
		{Rules: []Rule{{ID: "x", Effect: "maybe", Type: MatchDomain, Value: "example.com"}}},
		{Rules: []Rule{{ID: "x", Effect: Allow, Type: "bogus", Value: "example.com"}}},
		{Rules: []Rule{{ID: "x", Effect: Allow, Type: MatchDomain, Value: "  "}}},
	}
	for i, p := range cases {
		if _, err := Compile(p); err == nil {
			t.Errorf("case %d: expected compile error, got nil", i)
		}
	}
}
