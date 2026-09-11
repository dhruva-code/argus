package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// PhaseInfraMap is the Phase 3 key (mirrors app.seed_profiles.ALL_PHASES).
const PhaseInfraMap = "infrastructure_mapping"

// infraInfo is the enrichment for one IP.
type infraInfo struct {
	ASN      string
	ASNOrg   string
	Netblock string
	Country  string
	PTR      string
	Cloud    string
}

// enrichIP resolves ASN / netblock / country via Team Cymru's DNS service
// (no API key), the PTR record, and infers the cloud provider from the ASN
// organization name.
func enrichIP(ctx context.Context, res *net.Resolver, ip string) infraInfo {
	var info infraInfo
	rev := cymruReverse(ip)
	if rev == "" {
		return info
	}
	// origin lookup: "13335 | 104.16.0.0/12 | US | arin | 2011-02-11"
	if txts, err := res.LookupTXT(ctx, rev+".origin.asn.cymru.com"); err == nil && len(txts) > 0 {
		parts := splitPipe(txts[0])
		if len(parts) >= 3 {
			info.ASN = "AS" + strings.TrimSpace(firstField(parts[0]))
			info.Netblock = strings.TrimSpace(parts[1])
			info.Country = strings.TrimSpace(parts[2])
		}
	}
	// asn lookup: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
	if info.ASN != "" {
		q := fmt.Sprintf("%s.asn.cymru.com", strings.TrimPrefix(info.ASN, "AS"))
		if txts, err := res.LookupTXT(ctx, "AS"+q); err == nil && len(txts) > 0 {
			parts := splitPipe(txts[0])
			if len(parts) >= 5 {
				info.ASNOrg = strings.TrimSpace(parts[4])
			}
		}
	}
	if names, err := res.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		info.PTR = strings.TrimSuffix(names[0], ".")
	}
	info.Cloud = cloudFromASNOrg(info.ASNOrg, info.PTR)
	return info
}

// runInfraMapping enriches every resolved in-scope IP and emits infra assets +
// edges (ip → netblock → asn). It also records ip → ASN-org into `orgOut` (may
// be nil) for the WAF/CDN origin-intel phase.
func runInfraMapping(ctx context.Context, ips []string, orgOut map[string]string, cb Callbacks) {
	res := &net.Resolver{}
	done := 0
	for _, ip := range ips {
		if cb.cancelled() {
			return
		}
		info := enrichIP(ctx, res, ip)
		done++
		if orgOut != nil && info.ASNOrg != "" {
			orgOut[ip] = info.ASNOrg
		}

		attrsMap := map[string]string{}
		put := func(k, v string) {
			if v != "" {
				attrsMap[k] = v
			}
		}
		put("asn", info.ASN)
		put("asn_org", info.ASNOrg)
		put("netblock", info.Netblock)
		put("geo_country", info.Country)
		put("ptr", info.PTR)
		put("cloud_provider", info.Cloud)
		cb.Asset(Asset{
			Type: TypeIP, Value: ip, Status: StatusResolved,
			InScope: true, Sources: []string{"cymru"}, Infra: attrsMap,
		})

		if info.Netblock != "" {
			cb.Asset(Asset{Type: TypeNetblock, Value: info.Netblock, Status: StatusResolved,
				InScope: true, Sources: []string{"cymru"},
				Infra: map[string]string{"asn": info.ASN, "cloud_provider": info.Cloud}})
			cb.Edge(Edge{SrcType: TypeIP, SrcValue: ip, DstType: TypeNetblock, DstValue: info.Netblock, Kind: EdgeBelongsTo})
		}
		if info.ASN != "" {
			cb.Asset(Asset{Type: TypeASN, Value: info.ASN, Status: StatusResolved,
				InScope: true, Sources: []string{"cymru"},
				Infra: map[string]string{"asn_org": info.ASNOrg, "geo_country": info.Country}})
			from, to := info.Netblock, info.ASN
			if from == "" {
				from = ip
				cb.Edge(Edge{SrcType: TypeIP, SrcValue: from, DstType: TypeASN, DstValue: to, Kind: EdgeAnnouncedBy})
			} else {
				cb.Edge(Edge{SrcType: TypeNetblock, SrcValue: from, DstType: TypeASN, DstValue: to, Kind: EdgeAnnouncedBy})
			}
		}
	}
	cb.log("INFO", fmt.Sprintf("infrastructure mapping — enriched %d IP(s)", done))
}

// ── helpers ────────────────────────────────────────────────────────────────

func cymruReverse(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	}
	// IPv6 nibble form
	var sb strings.Builder
	for i := len(p) - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("%x.%x.", p[i]&0x0f, p[i]>>4))
	}
	return strings.TrimSuffix(sb.String(), ".")
}

func splitPipe(s string) []string { return strings.Split(s, "|") }

func firstField(s string) string {
	f := strings.Fields(s)
	if len(f) > 0 {
		return f[0]
	}
	return ""
}

var cloudASN = map[string]string{
	"CLOUDFLARENET":  "Cloudflare",
	"AMAZON":         "AWS",
	"AMAZON-02":      "AWS",
	"AMAZON-AES":     "AWS",
	"GOOGLE":         "Google Cloud",
	"GOOGLE-CLOUD":   "Google Cloud",
	"MICROSOFT":      "Azure",
	"MICROSOFT-CORP": "Azure",
	"FASTLY":         "Fastly",
	"AKAMAI":         "Akamai",
	"DIGITALOCEAN":   "DigitalOcean",
	"LINODE":         "Linode",
	"OVH":            "OVH",
	"HETZNER":        "Hetzner",
	"GITHUB":         "GitHub Pages",
}

func cloudFromASNOrg(org, ptr string) string {
	up := strings.ToUpper(org)
	for k, v := range cloudASN {
		if strings.Contains(up, k) {
			return v
		}
	}
	lp := strings.ToLower(ptr)
	switch {
	case strings.Contains(lp, "amazonaws.com"):
		return "AWS"
	case strings.Contains(lp, "1e100.net"), strings.Contains(lp, "googleusercontent"):
		return "Google Cloud"
	case strings.Contains(lp, "azure"), strings.Contains(lp, "cloudapp.net"):
		return "Azure"
	case strings.Contains(lp, "cloudflare"):
		return "Cloudflare"
	}
	return ""
}
