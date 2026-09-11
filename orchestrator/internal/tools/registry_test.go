package tools

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner implements plugin.Runner without touching the filesystem.
type fakeRunner struct {
	present map[string]string // binary -> version output
}

func (f fakeRunner) Look(bin string) (string, error) {
	if _, ok := f.present[bin]; ok {
		return "/fake/bin/" + bin, nil
	}
	return "", errors.New("not found")
}

func (f fakeRunner) Exec(_ context.Context, argv []string) (string, int, error) {
	bin := strings.TrimPrefix(argv[0], "/fake/bin/")
	if out, ok := f.present[bin]; ok {
		return out, 0, nil
	}
	return "", 1, errors.New("not found")
}

func TestBuiltInRegistry(t *testing.T) {
	reg := BuiltIn()
	for _, name := range []string{"subfinder", "dnsx", "httpx", "katana", "nuclei", "naabu", "ffuf"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("expected built-in tool %q", name)
		}
	}
	if len(reg.All()) < 7 {
		t.Errorf("expected >=7 tools, got %d", len(reg.All()))
	}
}

func TestHealthStates(t *testing.T) {
	reg := BuiltIn()
	r := fakeRunner{present: map[string]string{
		"subfinder": "Current Version: v2.16.0",
		"nuclei":    "Current Version: v2.9.0", // below min 3.0.0 -> degraded
		"httpx":     "totally unparseable",     // installed but no version -> degraded
	}}

	sub, _ := reg.Get("subfinder")
	if h := sub.Health(context.Background(), r); h.State != "ok" || h.InstalledVersion != "2.16.0" {
		t.Errorf("subfinder: got %+v", h)
	}

	nuc, _ := reg.Get("nuclei")
	if h := nuc.Health(context.Background(), r); h.State != "degraded" {
		t.Errorf("nuclei old version: got %+v", h)
	}

	hx, _ := reg.Get("httpx")
	if h := hx.Health(context.Background(), r); h.State != "degraded" {
		t.Errorf("httpx unparseable: got %+v", h)
	}

	kat, _ := reg.Get("katana")
	if h := kat.Health(context.Background(), r); h.State != "missing" {
		t.Errorf("katana missing: got %+v", h)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v2.16.0", "2.6.0", 1},
		{"3.0.0", "3.0.0", 0},
		{"v2.9.0", "v3.0.0", -1},
		{"1.11.2", "1.2.0", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
