package recon

import (
	"context"
	"testing"
)

// systemResolveFallback exists because dnsx performs its own raw DNS
// queries and never consults /etc/hosts — so a host that only resolves via
// a static hosts-file entry (TryHackMe .thm, HackTheBox .htb, any internal
// VPN lab) comes back from dnsx as unresolved, and the rest of the recon
// pipeline (merge_resolve_alive onward) silently has nothing to probe. This
// fallback uses the OS resolver instead, which does consult /etc/hosts.
func TestSystemResolveFallback_ResolvesHostsFileEntry(t *testing.T) {
	// "localhost" is guaranteed present in /etc/hosts (or NSS equivalent)
	// on essentially every Linux system, so it's a reliable stand-in for a
	// lab-only hostname without needing to mutate the test host's
	// /etc/hosts.
	rows := systemResolveFallback(context.Background(), []string{"localhost"})
	if len(rows) != 1 {
		t.Fatalf("expected 1 resolved row for localhost, got %d: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.Host != "localhost" {
		t.Errorf("expected host=localhost, got %q", row.Host)
	}
	if len(row.A) == 0 && len(row.AAAA) == 0 {
		t.Errorf("expected at least one A or AAAA record for localhost, got none: %+v", row)
	}
}

func TestSystemResolveFallback_SkipsUnresolvableHosts(t *testing.T) {
	rows := systemResolveFallback(context.Background(), []string{"this-host-does-not-exist.invalid"})
	if len(rows) != 0 {
		t.Fatalf("expected no rows for an unresolvable host, got %d: %+v", len(rows), rows)
	}
}

func TestSystemResolveFallback_MixedResolvableAndNot(t *testing.T) {
	rows := systemResolveFallback(context.Background(), []string{
		"localhost", "this-host-does-not-exist.invalid",
	})
	if len(rows) != 1 || rows[0].Host != "localhost" {
		t.Fatalf("expected exactly the resolvable host back, got %+v", rows)
	}
}

func TestSystemResolveFallback_EmptyInput(t *testing.T) {
	rows := systemResolveFallback(context.Background(), nil)
	if len(rows) != 0 {
		t.Fatalf("expected no rows for empty input, got %d", len(rows))
	}
}
