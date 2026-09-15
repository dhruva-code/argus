package recon

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
)

// PhaseVHost is the Phase 6 key.
const PhaseVHost = "vhost_enum"

// VHost is a virtual-host discovery emitted as a "vhost" event.
type VHost struct {
	IP             string  `json:"ip"`
	Hostname       string  `json:"hostname"`
	Scheme         string  `json:"scheme"`
	Port           int     `json:"port"`
	Classification string  `json:"classification"`
	StatusCode     int     `json:"status_code"`
	ResponseBytes  int     `json:"response_bytes"`
	Title          string  `json:"title"`
	Server         string  `json:"server"`
	BaselineStatus int     `json:"baseline_status"`
	BaselineBytes  int     `json:"baseline_bytes"`
	Similarity     float64 `json:"similarity"`
	InScope        bool    `json:"in_scope"`
}

const (
	vhClassDefault  = "default"
	vhClassInterest = "interesting"
	vhClassInternal = "potential_internal"
	vhClassUnusual  = "unusual_response"
)

var internalHint = regexp.MustCompile(`(?i)\b(internal|intranet|corp|vpn|admin|staging|stage|dev|test|uat|qa|local|preprod|private|backend|jenkins|gitlab|jira|confluence)\b`)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// runVHostEnum probes each in-scope IP with the candidate hostnames known to
// point at it, comparing every response against a random-Host baseline.
func runVHostEnum(ctx context.Context, he *httpengine.Engine, ipHosts map[string][]string, inScopeIP func(string) bool, inScopeHost func(string) bool, cb Callbacks) int {
	found := 0
	ips := sortedKeys(ipHosts)
	for _, ip := range ips {
		if cb.cancelled() {
			return found
		}
		if !inScopeIP(ip) {
			continue
		}
		base := fmt.Sprintf("https://%s/", ip)
		// The baseline probe's Host header only needs to be *unmatched* by
		// any real vhost — the literal IP itself already achieves that
		// (name-based vhosts key on ServerName/ServerAlias, which is never
		// the bare address) and, unlike an arbitrary made-up hostname, it
		// is inherently in scope: the caller already confirmed `ip` itself
		// is in scope via inScopeIP above, so the engine's scope check
		// (which authorizes by Host-header value — see httpengine.Engine.
		// check, deliberately strict so a *real* candidate hostname can't
		// be probed without its own scope approval) passes for exactly the
		// same reason the destination itself is authorized.
		bl, err := he.Do(ctx, "GET", base, ip)
		if err != nil {
			if httpengine.IsBlocked(err) {
				cb.log("WARNING", ip+": vhost baseline blocked ("+err.Error()+")")
			}
			continue
		}
		blTitle := extractTitle(bl.Body)
		cands := uniqSorted(ipHosts[ip])
		for _, host := range cands {
			if cb.cancelled() {
				return found
			}
			resp, err := he.Do(ctx, "GET", base, host)
			if err != nil {
				continue
			}
			sim := similarity(bl, resp, blTitle, extractTitle(resp.Body))
			cls := classifyVHost(host, bl, resp, sim, inScopeHost(host))
			if cls == vhClassDefault && sim > 0.9 {
				continue // uninteresting — matches the catch-all
			}
			found++
			cb.emitVHost(VHost{
				IP: ip, Hostname: host, Scheme: "https", Port: 443,
				Classification: cls,
				StatusCode:     resp.StatusCode, ResponseBytes: len(resp.Body),
				Title:          trim(extractTitle(resp.Body), 500),
				Server:         resp.Header.Get("Server"),
				BaselineStatus: bl.StatusCode, BaselineBytes: len(bl.Body),
				Similarity: sim, InScope: inScopeHost(host),
			})
			cb.Edge(Edge{SrcType: TypeIP, SrcValue: ip, DstType: TypeSubdomain, DstValue: host, Kind: EdgeServes})
		}
	}
	cb.log("INFO", fmt.Sprintf("virtual-host enumeration — %d interesting vhost(s) across %d IP(s)", found, len(ips)))
	return found
}

func classifyVHost(host string, bl, resp *httpengine.Response, sim float64, inScope bool) string {
	switch {
	case internalHint.MatchString(host):
		return vhClassInternal
	case resp.StatusCode >= 500 && bl.StatusCode < 500:
		return vhClassUnusual
	case sim > 0.9:
		return vhClassDefault
	case inScope:
		return vhClassInterest
	default:
		return vhClassInterest
	}
}

// similarity is a cheap 0..1 score: status match + body-size closeness + title
// match, equally weighted.
func similarity(a, b *httpengine.Response, at, bt string) float64 {
	score := 0.0
	if a.StatusCode == b.StatusCode {
		score += 0.4
	}
	la, lb := float64(len(a.Body)), float64(len(b.Body))
	if la == 0 && lb == 0 {
		score += 0.3
	} else {
		mx := la
		if lb > mx {
			mx = lb
		}
		diff := la - lb
		if diff < 0 {
			diff = -diff
		}
		score += 0.3 * (1 - diff/mx)
	}
	if strings.EqualFold(strings.TrimSpace(at), strings.TrimSpace(bt)) {
		score += 0.3
	}
	if score < 0 {
		return 0
	}
	return score
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

func uniqSorted(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		x = normHost(x)
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
