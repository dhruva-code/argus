// Package scope is the authoritative in-scope / out-of-scope decision engine.
//
// Every job the orchestrator runs, and every individual outbound request the
// HTTP engine makes, passes through Engine.Evaluate. A target is in scope only
// when an allow rule matches it and no deny rule matches it; the default is
// deny. Deny always wins.
//
// The Python gateway ships a byte-for-byte mirror of this logic
// (apis/gateway/app/scope). Both are exercised against
// testdata/fixtures/scope_cases.json — see scope_parity_test.go.
package scope

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Effect is the outcome a rule contributes when it matches.
type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// MatcherType selects how a rule's Value is compared against a target.
type MatcherType string

const (
	MatchDomain    MatcherType = "domain"    // exact host
	MatchSubdomain MatcherType = "subdomain" // host or any sub-label of it
	MatchWildcard  MatcherType = "wildcard"  // "*.example.com" (strict sub-label) or "*"
	MatchCIDR      MatcherType = "cidr"      // IPv4/IPv6 network contains target IP
	MatchIP        MatcherType = "ip"        // exact IP
	MatchASN       MatcherType = "asn"       // target ASN equals (AS-prefix optional)
	MatchURL       MatcherType = "url"       // scheme-insensitive host+path prefix
	MatchRegex     MatcherType = "regex"     // RE2 full match against host
)

// Rule is one line of a scope policy.
type Rule struct {
	ID     string      `json:"id"`
	Effect Effect      `json:"effect"`
	Type   MatcherType `json:"type"`
	Value  string      `json:"value"`
	Ports  []int       `json:"ports,omitempty"` // if set, rule only applies to these ports
	Paths  []string    `json:"paths,omitempty"` // if set, rule only applies to these path prefixes
}

// Policy is an ordered set of rules for one project.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// Target is the thing being checked. Any field may be zero; a rule that needs a
// field the target does not supply simply does not match.
type Target struct {
	Host string `json:"host,omitempty"`
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
	Path string `json:"path,omitempty"`
	ASN  string `json:"asn,omitempty"`
}

// Decision is the result of an evaluation.
type Decision struct {
	Allowed bool   `json:"allowed"`
	RuleID  string `json:"rule_id,omitempty"` // rule that decided; empty on default-deny
	Reason  string `json:"reason"`
}

// Engine holds a compiled policy. Compile once, evaluate many times.
type Engine struct {
	rules   []Rule
	regexps map[string]*regexp.Regexp
	nets    map[string]netip.Prefix
}

// Compile validates every rule and prepares matchers. It returns an error for a
// malformed CIDR or regex so a bad policy is rejected at save time, not at
// request time.
func Compile(p Policy) (*Engine, error) {
	e := &Engine{
		rules:   make([]Rule, len(p.Rules)),
		regexps: map[string]*regexp.Regexp{},
		nets:    map[string]netip.Prefix{},
	}
	copy(e.rules, p.Rules)
	for i, r := range p.Rules {
		if r.Effect != Allow && r.Effect != Deny {
			return nil, fmt.Errorf("rule %d (%s): invalid effect %q", i, r.ID, r.Effect)
		}
		switch r.Type {
		case MatchRegex:
			re, err := regexp.Compile(anchor(r.Value))
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): bad regex: %w", i, r.ID, err)
			}
			e.regexps[r.ID] = re
		case MatchCIDR:
			pfx, err := netip.ParsePrefix(r.Value)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): bad CIDR: %w", i, r.ID, err)
			}
			e.nets[r.ID] = pfx.Masked()
		case MatchDomain, MatchSubdomain, MatchWildcard, MatchIP, MatchASN, MatchURL:
			if strings.TrimSpace(r.Value) == "" {
				return nil, fmt.Errorf("rule %d (%s): empty value", i, r.ID)
			}
		default:
			return nil, fmt.Errorf("rule %d (%s): unknown matcher type %q", i, r.ID, r.Type)
		}
	}
	return e, nil
}

// Evaluate returns the scope decision for a target. Deny rules are checked
// first; if none match, allow rules; if none match, the target is denied.
func (e *Engine) Evaluate(t Target) Decision {
	nt := normalizeTarget(t)

	for _, r := range e.rules {
		if r.Effect == Deny && e.matches(r, nt) {
			return Decision{Allowed: false, RuleID: r.ID, Reason: "matched deny rule " + r.ID}
		}
	}
	for _, r := range e.rules {
		if r.Effect == Allow && e.matches(r, nt) {
			return Decision{Allowed: true, RuleID: r.ID, Reason: "matched allow rule " + r.ID}
		}
	}
	return Decision{Allowed: false, Reason: "no allow rule matched (default deny)"}
}

func (e *Engine) matches(r Rule, t Target) bool {
	if len(r.Ports) > 0 {
		if t.Port == 0 || !containsInt(r.Ports, t.Port) {
			return false
		}
	}
	if len(r.Paths) > 0 {
		if t.Path == "" || !hasAnyPrefix(t.Path, r.Paths) {
			return false
		}
	}
	return e.matchTarget(r, t)
}

func (e *Engine) matchTarget(r Rule, t Target) bool {
	switch r.Type {
	case MatchDomain:
		return t.Host != "" && t.Host == normalizeHost(r.Value)
	case MatchSubdomain:
		v := normalizeHost(r.Value)
		return t.Host != "" && (t.Host == v || strings.HasSuffix(t.Host, "."+v))
	case MatchWildcard:
		v := normalizeHost(r.Value)
		if v == "*" {
			return t.Host != ""
		}
		base := strings.TrimPrefix(v, "*.")
		return t.Host != "" && strings.HasSuffix(t.Host, "."+base) && t.Host != base
	case MatchIP:
		return t.IP != "" && ipEqual(t.IP, r.Value)
	case MatchCIDR:
		if t.IP == "" {
			return false
		}
		addr, err := netip.ParseAddr(t.IP)
		if err != nil {
			return false
		}
		return e.nets[r.ID].Contains(addr)
	case MatchASN:
		return t.ASN != "" && normalizeASN(t.ASN) == normalizeASN(r.Value)
	case MatchRegex:
		re := e.regexps[r.ID]
		return re != nil && t.Host != "" && re.MatchString(t.Host)
	case MatchURL:
		want := stripScheme(r.Value)
		if t.Host == "" {
			return false
		}
		got := t.Host + t.Path
		return strings.HasPrefix(got, want)
	default:
		return false
	}
}

// ── normalization helpers ───────────────────────────────────────────────────

func normalizeTarget(t Target) Target {
	t.Host = normalizeHost(t.Host)
	if t.IP != "" {
		if a, err := netip.ParseAddr(t.IP); err == nil {
			t.IP = a.String()
		}
	}
	if t.Path != "" && !strings.HasPrefix(t.Path, "/") {
		t.Path = "/" + t.Path
	}
	return t
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimSuffix(h, ".")
	return h
}

func normalizeASN(a string) string {
	a = strings.ToUpper(strings.TrimSpace(a))
	a = strings.TrimPrefix(a, "AS")
	return a
}

func stripScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	return strings.TrimSuffix(u, "/")
}

func anchor(re string) string {
	if !strings.HasPrefix(re, "^") {
		re = "^" + re
	}
	if !strings.HasSuffix(re, "$") {
		re += "$"
	}
	return re
}

func ipEqual(a, b string) bool {
	aa, err1 := netip.ParseAddr(a)
	bb, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return aa == bb
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
