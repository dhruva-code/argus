package ssrf

import "testing"

func TestGuardBlocksInternal(t *testing.T) {
	g, err := NewGuard(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5",
		"169.254.169.254", "100.100.100.200", "100.64.1.1",
		"::1", "fd00::1", "fe80::1", "0.0.0.0",
	}
	for _, ip := range blocked {
		if err := g.CheckAddr(ip); err == nil {
			t.Errorf("%s: expected block, got allow", ip)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "203.0.113.10", "2606:4700:4700::1111"}
	for _, ip := range allowed {
		if err := g.CheckAddr(ip); err != nil {
			t.Errorf("%s: expected allow, got %v", ip, err)
		}
	}
}

func TestGuardURLScheme(t *testing.T) {
	g, _ := NewGuard(nil, true)
	for _, u := range []string{"file:///etc/passwd", "gopher://x", "ftp://x/y"} {
		if err := g.CheckURL(u); err == nil {
			t.Errorf("%s: expected scheme rejection", u)
		}
	}
	if err := g.CheckURL("http://127.0.0.1:8000/admin"); err == nil {
		t.Error("expected loopback URL to be blocked")
	}
}

func TestGuardAllowOverride(t *testing.T) {
	g, err := NewGuard([]string{"10.0.0.0/8"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CheckAddr("10.1.2.3"); err != nil {
		t.Errorf("explicitly allowed CIDR should pass: %v", err)
	}
	if err := g.CheckAddr("192.168.1.1"); err == nil {
		t.Error("non-allowed private range should still block")
	}
}
