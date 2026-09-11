package recon

import (
	"context"
	"testing"

	"github.com/argus-platform/orchestrator/internal/scope"
)

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in, want string
		params   int
	}{
		{"/users/123", "/users/{id}", 1},
		{"/users/123/posts/456", "/users/{id}/posts/{id}", 2},
		{"/v1/9f1c8e3a-2b7d-4a11-9c3e-77aa01ffb210", "/v1/{uuid}", 1},
		{"/static/app.4f2a1b.js", "/static/app.4f2a1b.js", 0},
		{"/d41d8cd98f00b204e9800998ecf8427e", "/{hash}", 1},
		{"/", "/", 0},
		{"/about", "/about", 0},
	}
	for _, c := range cases {
		got, params := normalizePath(c.in)
		if got != c.want {
			t.Errorf("normalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
		if len(params) != c.params {
			t.Errorf("normalizePath(%q) params = %d, want %d", c.in, len(params), c.params)
		}
	}
}

func TestMakeEndpointDedupKeyAndScope(t *testing.T) {
	eng, _ := scope.Compile(scope.Policy{Rules: []scope.Rule{
		{ID: "a1", Effect: scope.Allow, Type: scope.MatchSubdomain, Value: "example.com"},
	}})

	a, ok := makeEndpoint("https://api.example.com/api/users/1?page=2&sort=name", "GET", eng, "katana")
	if !ok || !a.InScope {
		t.Fatalf("expected in-scope endpoint, got %+v", a)
	}
	b, _ := makeEndpoint("https://api.example.com/api/users/9999?sort=x&page=1", "GET", eng, "gau")
	if a.NormalizedURL != b.NormalizedURL {
		t.Errorf("expected same normalized url:\n  %s\n  %s", a.NormalizedURL, b.NormalizedURL)
	}
	if a.NormalizedURL != "api.example.com/api/users/{id}?page&sort" {
		t.Errorf("normalized = %q", a.NormalizedURL)
	}

	out, _ := makeEndpoint("https://evil.com/x", "GET", eng, "gau")
	if out.InScope {
		t.Error("evil.com endpoint should be out of scope")
	}

	if !contains(a.Tags, "api") {
		t.Errorf("expected 'api' tag, got %v", a.Tags)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestSyntheticM3Pipeline(t *testing.T) {
	t.Setenv("ARGUS_SYNTHETIC_RECON", "true")
	eng, guard := testEngine(t)

	var assets []Asset
	var vhosts []VHost
	var endpoints []Endpoint
	cb := Callbacks{
		Log:        func(_, _ string) {},
		Asset:      func(a Asset) { assets = append(assets, a) },
		Edge:       func(Edge) {},
		VHost:      func(v VHost) { vhosts = append(vhosts, v) },
		Endpoint:   func(e Endpoint) { endpoints = append(endpoints, e) },
		Checkpoint: func(string, map[string]any) {},
		Cancelled:  func() bool { return false },
	}
	var secrets []Secret
	var repos []Repository
	var ports []Port
	var findings []Finding
	cb.Secret = func(s Secret) { secrets = append(secrets, s) }
	cb.Repo = func(r Repository) { repos = append(repos, r) }
	cb.Port = func(p Port) { ports = append(ports, p) }
	cb.Finding = func(f Finding) { findings = append(findings, f) }

	res, err := Run(context.Background(), eng, guard, nil, Options{
		Roots: []string{"example.com"}, MaxTargets: 200, VulnLevel: VulnLevelAggressive,
		Phases: []string{
			PhasePassiveEnum, PhaseActiveEnum, PhaseMergeAlive,
			PhaseInfraMap, PhaseWAFCDN, PhaseVHost, PhaseEndpoints,
			PhaseJSAnalysis, PhaseDirDiscovery, PhaseSourceIntel,
			PhasePortScan, PhaseVulnScan,
		},
	}, cb)
	if err != nil {
		t.Fatal(err)
	}

	if len(ports) == 0 || res.Ports == 0 {
		t.Error("expected synthetic open ports")
	}
	var sawWebPort, sawSSH bool
	for _, p := range ports {
		if p.Service == "ssh" {
			sawSSH = true
		}
		if p.HTTPStatus > 0 {
			sawWebPort = true
		}
	}
	if !sawSSH || !sawWebPort {
		t.Errorf("port coverage: ssh=%v web=%v", sawSSH, sawWebPort)
	}
	if len(findings) == 0 || res.Findings == 0 {
		t.Error("expected synthetic vuln findings")
	}
	var sawCritical, sawOOB, sawEdge, sawOrigin, sawInjection bool
	for _, f := range findings {
		if f.Fingerprint == "" || f.TemplateID == "" {
			t.Errorf("finding missing fingerprint/template: %+v", f)
		}
		if f.Severity == "critical" && len(f.CVE) > 0 {
			sawCritical = true
		}
		if f.OOBConfirmed {
			sawOOB = true
		}
		if f.Engine == "waf-cdn" && contains(f.Tags, "edge") {
			sawEdge = true
		}
		if f.TemplateID == "origin-ip-exposed" {
			sawOrigin = true
		}
		if f.Engine == "nuclei-dast" && contains(f.Tags, "injection") {
			sawInjection = true
		}
	}
	if !sawCritical {
		t.Error("expected a critical synthetic finding with a CVE")
	}
	if !sawOOB {
		t.Error("expected OOB-confirmed findings")
	}
	if !sawEdge || !sawOrigin {
		t.Errorf("waf/cdn phase coverage: edge=%v origin=%v", sawEdge, sawOrigin)
	}
	if !sawInjection {
		t.Error("expected an injection finding at the aggressive level")
	}

	if len(secrets) == 0 {
		t.Error("expected synthetic secrets (JS + repo)")
	}
	if len(repos) == 0 {
		t.Error("expected synthetic repositories")
	}
	var sawRepoSecret, sawJSSecret, sawSensitiveEndpoint bool
	for _, s := range secrets {
		if s.SourceKind == "repo" {
			sawRepoSecret = true
		}
		if s.SourceKind == "js" {
			sawJSSecret = true
		}
		if s.Fingerprint == "" || s.Value == "" {
			t.Errorf("secret missing fingerprint/value: %+v", s)
		}
	}
	for _, e := range endpoints {
		if e.Sensitivity == "critical" {
			sawSensitiveEndpoint = true
		}
	}
	if !sawRepoSecret || !sawJSSecret {
		t.Errorf("secret source coverage: repo=%v js=%v", sawRepoSecret, sawJSSecret)
	}
	if !sawSensitiveEndpoint {
		t.Error("expected a critical-sensitivity endpoint from synthetic dir discovery")
	}

	var sawASN, sawNetblock, sawCloud bool
	for _, a := range assets {
		switch a.Type {
		case TypeASN:
			sawASN = true
		case TypeNetblock:
			sawNetblock = true
		}
		if a.Infra["cloud_provider"] != "" {
			sawCloud = true
		}
	}
	if !sawASN || !sawNetblock || !sawCloud {
		t.Errorf("infra: asn=%v netblock=%v cloud=%v", sawASN, sawNetblock, sawCloud)
	}
	if len(vhosts) == 0 {
		t.Error("expected synthetic vhosts")
	}
	if len(endpoints) == 0 {
		t.Error("expected synthetic endpoints")
	}
	var sawTemplated, sawGraphQL bool
	for _, e := range endpoints {
		if e.Method == "POST" && contains(e.Tags, "graphql") {
			sawGraphQL = true
		}
		for _, p := range e.Params {
			if p.In == "path" {
				sawTemplated = true
			}
		}
	}
	if !sawTemplated {
		t.Error("expected at least one templated path param")
	}
	if !sawGraphQL {
		t.Error("expected a graphql-tagged endpoint")
	}
}
