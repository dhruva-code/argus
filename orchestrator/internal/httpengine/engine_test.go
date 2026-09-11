package httpengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/argus-platform/orchestrator/internal/scope"
	"github.com/argus-platform/orchestrator/internal/ssrf"
)

func newEngine(t *testing.T, rules []scope.Rule, allowCIDRs []string) *Engine {
	t.Helper()
	sc, err := scope.Compile(scope.Policy{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	g, err := ssrf.NewGuard(allowCIDRs, true)
	if err != nil {
		t.Fatal(err)
	}
	return New(sc, g, Options{RequestsPerSecond: 100, TimeoutSeconds: 5})
}

func TestScopeRejection(t *testing.T) {
	e := newEngine(t, []scope.Rule{
		{ID: "a1", Effect: scope.Allow, Type: scope.MatchSubdomain, Value: "example.com"},
	}, nil)
	_, err := e.Get(context.Background(), "https://evil.com/")
	if !IsBlocked(err) {
		t.Fatalf("expected scope block, got %v", err)
	}
	if _, ok := err.(*ScopeError); !ok {
		t.Errorf("expected *ScopeError, got %T", err)
	}
}

func TestSSRFRejection(t *testing.T) {
	// example.com is in scope by name, but resolves publicly; use a loopback
	// literal instead which is in scope only if we allow it, then SSRF blocks.
	e := newEngine(t, []scope.Rule{
		{ID: "a1", Effect: scope.Allow, Type: scope.MatchIP, Value: "127.0.0.1"},
	}, nil)
	_, err := e.Get(context.Background(), "http://127.0.0.1:9/")
	if !IsBlocked(err) {
		t.Fatalf("expected SSRF block, got %v", err)
	}
	if _, ok := err.(*SSRFError); !ok {
		t.Errorf("expected *SSRFError, got %T", err)
	}
}

func TestAllowedRequestWithHostHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Vhost", r.Host)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	defer srv.Close()

	// Allow the test server's loopback address explicitly (scope + SSRF).
	e := newEngine(t, []scope.Rule{
		{ID: "a1", Effect: scope.Allow, Type: scope.MatchIP, Value: "127.0.0.1"},
		{ID: "a2", Effect: scope.Allow, Type: scope.MatchSubdomain, Value: "vhost.test"},
	}, []string{"127.0.0.0/8"})

	resp, err := e.Do(context.Background(), "GET", srv.URL+"/", "app.vhost.test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Vhost") != "app.vhost.test" {
		t.Errorf("Host header not applied: %q", resp.Header.Get("X-Vhost"))
	}
}

func TestResponseCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		big := make([]byte, 1<<20)
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	sc, _ := scope.Compile(scope.Policy{Rules: []scope.Rule{
		{ID: "a1", Effect: scope.Allow, Type: scope.MatchIP, Value: "127.0.0.1"},
	}})
	g, _ := ssrf.NewGuard([]string{"127.0.0.0/8"}, true)
	e := New(sc, g, Options{RequestsPerSecond: 100, MaxResponseBytes: 4096})

	resp, err := e.Get(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != 4096 || !resp.Truncated {
		t.Errorf("body=%d truncated=%v, want 4096/true", len(resp.Body), resp.Truncated)
	}
}
