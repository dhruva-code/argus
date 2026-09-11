package recon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
	"github.com/argus-platform/orchestrator/internal/scope"
)

// PhaseWAFCDN is the Phase 4 key.
const PhaseWAFCDN = "waf_cdn_origin_intel"

// signature of a CDN / WAF, matched against response headers (lower-cased).
type edgeSig struct {
	name   string
	kind   string // cdn | waf
	header string // header name that must be present
	value  string // optional substring the header value must contain ("" = any)
}

var edgeSignatures = []edgeSig{
	{"Cloudflare", "cdn", "cf-ray", ""},
	{"Cloudflare", "waf", "server", "cloudflare"},
	{"Akamai", "cdn", "x-akamai-transformed", ""},
	{"Akamai", "cdn", "x-akamai-request-id", ""},
	{"Amazon CloudFront", "cdn", "x-amz-cf-id", ""},
	{"Amazon CloudFront", "cdn", "via", "cloudfront"},
	{"Fastly", "cdn", "x-served-by", "cache-"},
	{"Fastly", "cdn", "x-fastly-request-id", ""},
	{"Sucuri", "waf", "x-sucuri-id", ""},
	{"Sucuri", "waf", "server", "sucuri"},
	{"Imperva Incapsula", "waf", "x-iinfo", ""},
	{"Imperva Incapsula", "waf", "x-cdn", "incapsula"},
	{"F5 BIG-IP", "waf", "server", "big-ip"},
	{"Barracuda", "waf", "server", "barracuda"},
	{"AWS WAF / ALB", "waf", "x-amzn-requestid", ""},
	{"Azure Front Door", "cdn", "x-azure-ref", ""},
	{"Vercel", "cdn", "x-vercel-id", ""},
	{"Netlify", "cdn", "x-nf-request-id", ""},
	{"Google Cloud CDN", "cdn", "via", "google"},
	{"KeyCDN", "cdn", "server", "keycdn"},
	{"StackPath", "cdn", "x-hw", ""},
}

// cloud/CDN ASN-org fragments — an IP announced by one of these is edge, not origin.
var cdnASNHints = []string{
	"cloudflare", "akamai", "fastly", "amazon", "cloudfront", "google",
	"microsoft", "azure", "incapsula", "imperva", "sucuri", "stackpath",
	"highwinds", "edgecast", "verizon", "limelight", "cdn",
}

// runWAFCDNIntel is Phase 4: fingerprint the WAF/CDN in front of each alive host
// from its response headers, then look for an exposed origin by probing a few
// origin-revealing hostnames and flagging any resolved IP that is not announced
// by a CDN/cloud AS.
func runWAFCDNIntel(
	ctx context.Context, he *httpengine.Engine, eng *scope.Engine,
	aliveBase map[string]string, resolved map[string]resolvedHost,
	ipASNOrg map[string]string, roots []string, cb Callbacks,
) int {
	hosts := make([]string, 0, len(aliveBase))
	for h := range aliveBase {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	edgeByHost := map[string]string{} // host -> "Cloudflare (cdn)"
	n := 0
	for _, h := range hosts {
		if cb.cancelled() {
			break
		}
		resp, err := he.Do(ctx, "GET", aliveBase[h], "")
		if err != nil {
			continue
		}
		hdr := map[string]string{}
		for k := range resp.Header {
			hdr[strings.ToLower(k)] = strings.ToLower(resp.Header.Get(k))
		}
		seen := map[string]bool{}
		for _, s := range edgeSignatures {
			v, ok := hdr[s.header]
			if !ok || (s.value != "" && !strings.Contains(v, s.value)) {
				continue
			}
			key := s.name + "|" + s.kind
			if seen[key] {
				continue
			}
			seen[key] = true
			edgeByHost[h] = s.name + " (" + s.kind + ")"
			cb.Asset(Asset{
				Type: subOrDomain(h, roots), Value: h, Status: StatusAlive, InScope: true,
				Sources:      []string{"waf-cdn"},
				Technologies: []string{s.name},
				Tags:         []string{s.kind},
			})
			f := Finding{
				Fingerprint:    findingFingerprint("edge-"+s.kind+"-"+strings.ToLower(s.name), h, "/", ""),
				TemplateID:     "edge-" + s.kind + "-fingerprint",
				Name:           s.name + " " + strings.ToUpper(s.kind) + " detected",
				Severity:       "info",
				Engine:         "waf-cdn",
				Tags:           []string{s.kind, "edge"},
				Host:           h,
				MatchedAt:      aliveBase[h],
				NormalizedPath: "/",
				Description:    fmt.Sprintf("%s response header identifies %s in front of this host.", s.header, s.name),
				Level:          VulnLevelPassive,
				InScope:        true,
			}
			cb.emitFinding(f)
			n++
		}
	}

	// origin discovery for the CDN-fronted hosts
	originHosts := []string{"origin", "direct", "cpanel", "webmail", "ftp", "mail", "dev", "staging"}
	checked := map[string]bool{}
	for _, root := range roots {
		for _, pfx := range originHosts {
			cand := pfx + "." + root
			if checked[cand] || !eng.Evaluate(scope.Target{Host: cand}).Allowed {
				continue
			}
			checked[cand] = true
			rh, ok := resolved[cand]
			if !ok || len(rh.ips) == 0 {
				continue
			}
			for _, ip := range rh.ips {
				if isCDNAddr(ip, ipASNOrg) {
					continue
				}
				cb.Asset(Asset{
					Type: TypeSubdomain, Value: cand, Status: StatusResolved, InScope: true,
					Sources: []string{"waf-cdn"}, IPAddresses: []string{ip},
					Tags: []string{"origin-candidate"},
				})
				cb.emitFinding(Finding{
					Fingerprint:    findingFingerprint("origin-ip-exposed", cand, "/", ip),
					TemplateID:     "origin-ip-exposed",
					Name:           "Possible origin IP behind CDN",
					Severity:       "medium",
					Engine:         "waf-cdn",
					Tags:           []string{"origin", "edge-bypass"},
					Host:           cand,
					MatchedAt:      cand,
					NormalizedPath: "/",
					Extracted:      []string{ip},
					Description: fmt.Sprintf(
						"%s resolves to %s, which is not announced by a CDN/cloud AS — a request "+
							"with the right Host header may bypass the CDN/WAF protecting the main site.", cand, ip),
					Remediation: "Firewall the origin so it only accepts traffic from the CDN's published ranges; " +
						"rotate the origin IP if it has leaked.",
					Level:   VulnLevelPassive,
					InScope: true,
				})
				n++
			}
		}
	}

	cb.log("INFO", fmt.Sprintf("waf/cdn & origin intel — %d edge fingerprint(s), %d host(s) fronted", n, len(edgeByHost)))
	return n
}

func isCDNAddr(ip string, ipASNOrg map[string]string) bool {
	if org, ok := ipASNOrg[ip]; ok {
		lo := strings.ToLower(org)
		for _, h := range cdnASNHints {
			if strings.Contains(lo, h) {
				return true
			}
		}
	}
	// RFC1918 etc. are never a public origin worth reporting
	if p := net.ParseIP(ip); p != nil && (p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast()) {
		return true
	}
	return false
}
