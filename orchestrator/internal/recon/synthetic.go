package recon

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/argus-platform/orchestrator/internal/scope"
)

// The synthetic surface is deterministic per root domain so tests and offline
// dev runs are reproducible. Enable with ARGUS_SYNTHETIC_RECON=true.

var synthLabels = []string{"www", "api", "app", "dev", "staging", "admin", "mail", "vpn", "cdn", "blog"}

func synthIP(seed string) string {
	h := sha256.Sum256([]byte(seed))
	// 203.0.113.0/24 is RFC 5737 TEST-NET-3 — safe placeholder space.
	return fmt.Sprintf("203.0.113.%d", int(h[0])%254+1)
}

func syntheticSubdomains(roots []string) map[string][]string {
	out := map[string][]string{}
	for _, root := range roots {
		out[normHost(root)] = []string{"scope"}
		h := sha256.Sum256([]byte(root))
		n := int(h[1])%6 + 4 // 4..9 subdomains
		for i := 0; i < n && i < len(synthLabels); i++ {
			host := synthLabels[i] + "." + normHost(root)
			srcs := []string{"subfinder:crtsh"}
			if i%2 == 0 {
				srcs = append(srcs, "assetfinder")
			}
			if i%3 == 0 {
				srcs = append(srcs, "subfinder:otx")
			}
			out[host] = srcs
		}
		// one deterministic out-of-scope neighbour
		out["marketing."+normHost(root)+".cdn-partner.test"] = []string{"subfinder:otx"}
	}
	return out
}

func syntheticResolve(hosts []string) []dnsxRow {
	var rows []dnsxRow
	for _, h := range hosts {
		hh := sha256.Sum256([]byte(h))
		if binary.BigEndian.Uint16(hh[:2])%10 == 0 {
			continue // ~10% NXDOMAIN
		}
		row := dnsxRow{Host: h, StatusCode: "NOERROR", A: []string{synthIP(h)}}
		if len(h) > 0 && h[0]%3 == 0 {
			row.CNAME = []string{"edge." + h + ".synthetic-cdn.test"}
		}
		rows = append(rows, row)
	}
	return rows
}

func syntheticHTTP(hosts []string) []httpxRow {
	var rows []httpxRow
	servers := []string{"nginx", "cloudflare", "Apache/2.4.52", "envoy", "Microsoft-IIS/10.0"}
	techs := [][]string{{"Nginx"}, {"Cloudflare", "React"}, {"Apache", "PHP", "WordPress"}, {"Envoy"}, {"ASP.NET"}}
	for _, h := range hosts {
		sum := sha256.Sum256([]byte("http:" + h))
		if sum[0]%5 == 0 {
			continue // ~20% not listening on http
		}
		status := 200
		switch sum[1] % 6 {
		case 1:
			status = 301
		case 2:
			status = 403
		case 3:
			status = 404
		case 4:
			status = 500
		}
		i := int(sum[2]) % len(servers)
		row := httpxRow{
			URL: "https://" + h, Input: h, Host: synthIP(h),
			StatusCode: status, Title: "Synthetic service — " + h,
			Webserver: servers[i], Tech: techs[i], Scheme: "https", Port: "443",
			ContentType: "text/html",
		}
		row.TLS = &struct {
			SubjectAN []string `json:"subject_an"`
			SubjectCN string   `json:"subject_cn"`
		}{SubjectAN: []string{h, "*." + h}, SubjectCN: h}
		if status == 301 {
			row.Location = "https://www." + h + "/"
		}
		rows = append(rows, row)
	}
	return rows
}

// ── synthetic M3 surface ──────────────────────────────────────────────────

func runSyntheticInfra(ips []string, orgOut map[string]string, cb Callbacks) {
	providers := []string{"Cloudflare", "AWS", "Google Cloud", "Fastly", ""}
	orgs := []string{"CLOUDFLARENET", "AMAZON-02", "GOOGLE", "FASTLY", "EXAMPLE-AS"}
	for _, ip := range ips {
		h := sha256.Sum256([]byte("infra:" + ip))
		i := int(h[0]) % len(providers)
		asn := fmt.Sprintf("AS%d", 13000+int(binary.BigEndian.Uint16(h[1:3]))%50000)
		nb := ip[:len(ip)-len(lastOctet(ip))] + "0/24"
		if orgOut != nil {
			orgOut[ip] = orgs[i]
		}
		cb.Asset(Asset{Type: TypeIP, Value: ip, Status: StatusResolved, InScope: true,
			Sources: []string{"cymru"}, Infra: map[string]string{
				"asn": asn, "asn_org": orgs[i], "netblock": nb,
				"geo_country": "US", "ptr": "host-" + lastOctet(ip) + ".synthetic.test",
				"cloud_provider": providers[i],
			}})
		cb.Asset(Asset{Type: TypeNetblock, Value: nb, Status: StatusResolved, InScope: true,
			Sources: []string{"cymru"}, Infra: map[string]string{"asn": asn, "cloud_provider": providers[i]}})
		cb.Asset(Asset{Type: TypeASN, Value: asn, Status: StatusResolved, InScope: true,
			Sources: []string{"cymru"}, Infra: map[string]string{"asn_org": orgs[i], "geo_country": "US"}})
		cb.Edge(Edge{SrcType: TypeIP, SrcValue: ip, DstType: TypeNetblock, DstValue: nb, Kind: EdgeBelongsTo})
		cb.Edge(Edge{SrcType: TypeNetblock, SrcValue: nb, DstType: TypeASN, DstValue: asn, Kind: EdgeAnnouncedBy})
	}
	cb.log("INFO", fmt.Sprintf("infrastructure mapping — enriched %d IP(s)", len(ips)))
}

func lastOctet(ip string) string {
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == '.' {
			return ip[i+1:]
		}
	}
	return ip
}

func runSyntheticVHosts(ipHosts map[string][]string, cb Callbacks) {
	n := 0
	for ip, hosts := range ipHosts {
		for _, h := range uniqSorted(hosts) {
			sum := sha256.Sum256([]byte("vhost:" + ip + h))
			if sum[0]%3 != 0 {
				continue
			}
			cls := vhClassInterest
			if internalHint.MatchString(h) {
				cls = vhClassInternal
			}
			cb.emitVHost(VHost{
				IP: ip, Hostname: h, Scheme: "https", Port: 443, Classification: cls,
				StatusCode: 200, ResponseBytes: 4096 + int(sum[1])*10, Title: "Synthetic vhost " + h,
				Server: "nginx", BaselineStatus: 404, BaselineBytes: 512, Similarity: 0.3, InScope: true,
			})
			cb.Edge(Edge{SrcType: TypeIP, SrcValue: ip, DstType: TypeSubdomain, DstValue: h, Kind: EdgeServes})
			n++
		}
	}
	cb.log("INFO", fmt.Sprintf("virtual-host enumeration — %d interesting vhost(s)", n))
}

func runSyntheticEndpoints(aliveHosts, _ []string, eng *scope.Engine, cb Callbacks) int {
	tmpls := []struct {
		method, path string
	}{
		{"GET", "/"},
		{"GET", "/api/users/1042"},
		{"GET", "/api/users/9f1c8e3a-2b7d-4a11-9c3e-77aa01ffb210"},
		{"POST", "/api/login"},
		{"GET", "/admin"},
		{"GET", "/swagger.json"},
		{"POST", "/graphql"},
		{"GET", "/static/app.4f2a1b.js"},
		{"GET", "/v2/orders/8837?expand=items"},
	}
	n := 0
	for _, host := range aliveHosts {
		for _, t := range tmpls {
			if ep, ok := makeEndpoint("https://"+host+t.path, t.method, eng, "synthetic"); ok && ep.InScope {
				cb.emitEndpoint(ep)
				n++
			}
		}
	}
	cb.log("INFO", fmt.Sprintf("url_endpoint_discovery — %d endpoint(s)", n))
	return n
}

// ── synthetic M4 surface ──────────────────────────────────────────────────

func runSyntheticJS(aliveHosts []string, eng *scope.Engine, cb Callbacks) {
	types := []string{"AWS", "GitHubToken", "JWT", "GoogleAPIKey", "SlackToken"}
	n := 0
	for i, h := range aliveHosts {
		if i%2 == 1 {
			continue
		}
		jsURL := "https://" + h + "/static/app.4f2a1b.js"
		dt := types[i%len(types)]
		raw := "synthetic-" + dt + "-" + h + "-000000000000000000"
		s := newSecret(dt, "custom", "js:"+jsURL+":42", raw, false)
		s.SourceKind = "js"
		s.Source = jsURL
		cb.emitSecret(s)
		n++
		// a referenced internal endpoint
		if ep, ok := makeEndpoint("https://"+h+"/api/internal/config", "GET", eng, "js"); ok && ep.InScope {
			ep.Tags = []string{"js-ref", "api", "admin"}
			cb.emitEndpoint(ep)
		}
		// source map
		if ep, ok := makeEndpoint(jsURL+".map", "GET", eng, "js"); ok && ep.InScope {
			ep.Tags = []string{"source-map"}
			cb.emitEndpoint(ep)
		}
	}
	cb.log("INFO", fmt.Sprintf("JavaScript analysis — %d secret candidate(s)", n))
}

func runSyntheticDirs(aliveHosts []string, eng *scope.Engine, cb Callbacks) {
	paths := []struct{ p, sev, why string }{
		{"/.git/config", "critical", "Exposed .git directory — full source history recoverable"},
		{"/.env", "critical", "Environment file — likely credentials / configuration exposure"},
		{"/backup.sql", "high", "Backup / archive file"},
		{"/admin/", "medium", "Admin panel"},
		{"/server-status", "medium", "Apache status page"},
		{"/.well-known/security.txt", "none", "security.txt (informational)"},
	}
	n := 0
	for i, h := range aliveHosts {
		if i > 2 {
			break
		}
		for _, x := range paths {
			ep, ok := makeEndpoint("https://"+h+x.p, "GET", eng, "ffuf")
			if !ok || !ep.InScope {
				continue
			}
			ep.StatusCode = 200
			ep.ContentLength = 1024
			ep.Sensitivity = x.sev
			ep.SensitivityReason = x.why
			ep.Tags = []string{"content-discovery"}
			if x.sev != "none" {
				ep.Tags = append(ep.Tags, "sensitive")
			}
			cb.emitEndpoint(ep)
			n++
		}
	}
	cb.log("INFO", fmt.Sprintf("directory discovery — %d path(s)", n))
}

func runSyntheticRepos(roots []string, cb Callbacks) {
	for _, root := range roots {
		org := root
		if i := len(root); i > 0 {
			org = root[:len(root)-len(tld(root))-1]
		}
		for _, name := range []string{"web", "api", "infra", "mobile"} {
			full := org + "/" + name
			rp := Repository{
				Provider: "github", FullName: full,
				URL:         "https://github.com/" + full,
				Description: "Synthetic repo for " + root, DefaultBranch: "main",
				DiscoveredVia: "org:" + org, MatchedTerms: []string{root},
				IaCFiles: []string{"docker", "terraform"}, InScope: true,
				Stars: 12,
			}
			cb.emitRepo(rp)
			if name == "infra" {
				s := newSecret("AWS", "trufflehog", full+"/terraform/main.tf:88",
					"synthetic-AWS-repo-000000000000000000", false)
				s.SourceKind = "repo"
				s.Source = rp.URL
				cb.emitSecret(s)
			}
		}
	}
	cb.log("INFO", "source-code intelligence — synthetic repos emitted")
}

func runSyntheticWAFCDN(aliveBase map[string]string, roots []string, cb Callbacks) int {
	n := 0
	i := 0
	for h := range aliveBase {
		edge, kind := "Cloudflare", "cdn"
		if i%2 == 1 {
			edge, kind = "Imperva Incapsula", "waf"
		}
		i++
		cb.Asset(Asset{
			Type: subOrDomain(h, roots), Value: h, Status: StatusAlive, InScope: true,
			Sources: []string{"waf-cdn"}, Technologies: []string{edge}, Tags: []string{kind},
		})
		cb.emitFinding(Finding{
			Fingerprint: findingFingerprint("edge-"+kind+"-"+strings.ToLower(edge), h, "/", ""),
			TemplateID:  "edge-" + kind + "-fingerprint",
			Name:        edge + " " + strings.ToUpper(kind) + " detected",
			Severity:    "info", Engine: "waf-cdn", Tags: []string{kind, "edge"},
			Host: h, MatchedAt: aliveBase[h], NormalizedPath: "/",
			Level: VulnLevelPassive, InScope: true,
		})
		n++
	}
	for _, root := range roots {
		cand := "origin." + root
		cb.emitFinding(Finding{
			Fingerprint: findingFingerprint("origin-ip-exposed", cand, "/", "198.51.100.7"),
			TemplateID:  "origin-ip-exposed",
			Name:        "Possible origin IP behind CDN",
			Severity:    "medium", Engine: "waf-cdn", Tags: []string{"origin", "edge-bypass"},
			Host: cand, MatchedAt: cand, NormalizedPath: "/", Extracted: []string{"198.51.100.7"},
			Level: VulnLevelPassive, InScope: true,
		})
		n++
	}
	cb.log("INFO", fmt.Sprintf("waf/cdn & origin intel — %d synthetic signal(s)", n))
	return n
}

func runSyntheticInjection(aliveHosts []string, eng *scope.Engine, cb Callbacks) (int, int) {
	pts, finds := 0, 0
	specs := []struct {
		param, class, tier, method string
	}{
		{"q", "sqli", "verified", "error_based"},
		{"redirect", "open_redirect", "verified", "redirect_location"},
		{"id", "xss", "likely", "reflection"},
		{"file", "path_traversal", "verified", "self_reference_traversal"},
	}
	for i, h := range aliveHosts {
		if i > 1 || !eng.Evaluate(scope.Target{Host: h}).Allowed {
			continue
		}
		for _, s := range specs {
			url := "https://" + h + "/search?" + s.param + "=1"
			cb.emitInjPoint(InjPointRecord{
				Method: "GET", URL: "https://" + h + "/search", Host: h,
				ParamName: s.param, Location: "query", ParamType: "string",
				AuthState: "unauthenticated", CandidateClasses: []string{s.class},
				TestedClasses: []string{s.class}, BestResult: s.tier, Confidence: 85,
			})
			pts++
			sev := "high"
			if s.class == "sqli" {
				sev = "critical"
			}
			cb.emitFinding(Finding{
				Fingerprint: findingFingerprint("injection-"+s.class, h, "/search", s.param),
				TemplateID:  "injection-" + s.class,
				Name:        "Synthetic " + s.class + " finding",
				Severity:    sev, Engine: "injection-engine",
				Tags: []string{"injection", s.class, s.tier, "synthetic"},
				Host: h, MatchedAt: url, NormalizedPath: "/search",
				MatcherName: s.method, Level: VulnLevelAggressive,
				OOBConfirmed: s.method == "oast_callback", InScope: true,
			})
			finds++
		}
	}
	cb.log("INFO", fmt.Sprintf("injection testing — %d synthetic parameter(s), %d finding(s)", pts, finds))
	return pts, finds
}

func runSyntheticPorts(ips []string, ipHosts map[string][]string, cb Callbacks) int {
	spec := []struct {
		port           int
		svc, prod, ver string
		tls            bool
	}{
		{22, "ssh", "OpenSSH", "8.9p1", false},
		{80, "http", "nginx", "1.24.0", false},
		{443, "https", "nginx", "1.24.0", true},
		{8080, "http-alt", "Jetty", "9.4.44", false},
	}
	n := 0
	for i, ip := range ips {
		if i > 3 {
			break
		}
		for _, s := range spec {
			p := Port{
				IP: ip, Port: s.port, Protocol: "tcp", State: "open",
				Service: s.svc, Product: s.prod, Version: s.ver, TLS: s.tls,
				Hostnames: uniqSorted(ipHosts[ip]), Source: "naabu", InScope: true,
			}
			if s.svc == "http" || s.svc == "https" || s.svc == "http-alt" {
				p.HTTPStatus = 200
				p.HTTPTitle = "Synthetic service on " + ip
			}
			cb.emitPort(p)
			n++
		}
	}
	cb.log("INFO", fmt.Sprintf("port scan — %d synthetic open port(s)", n))
	return n
}

func runSyntheticFindings(aliveHosts []string, level string, eng *scope.Engine, cb Callbacks) int {
	specs := []struct {
		id, name, sev, path, matcher string
		cve                          []string
		cvss                         float64
	}{
		{"phpinfo-files", "PHPinfo Page - Detect", "low", "/info.php", "", nil, 0},
		{"wordpress-db-exposure", "WordPress Database Backup File - Exposure", "high", "/db.sql", "", nil, 7.5},
		{"http-missing-security-headers", "HTTP Missing Security Headers", "info", "/", "content-security-policy", nil, 0},
		{"CVE-2021-44228", "Apache Log4j RCE", "critical", "/api", "", []string{"CVE-2021-44228"}, 10.0},
		{"tech-detect", "Wappalyzer Technology Detection", "info", "/", "nginx", nil, 0},
	}
	n := 0
	for i, h := range aliveHosts {
		if i > 2 {
			break
		}
		if !eng.Evaluate(scope.Target{Host: h}).Allowed {
			continue
		}
		for _, s := range specs {
			np, _ := normalizePath(s.path)
			f := Finding{
				Fingerprint: findingFingerprint(s.id, h, np, s.matcher),
				TemplateID:  s.id, Name: s.name, Severity: s.sev,
				Engine: "nuclei", TemplateVersion: "v10.4.8",
				Tags: []string{"synthetic"},
				Host: h, MatchedAt: "https://" + h + s.path, NormalizedPath: np,
				MatcherName: s.matcher, CVE: s.cve, CVSSScore: s.cvss,
				Level: level, InScope: true,
				ResponseExcerpt: "HTTP/1.1 200 OK\r\n\r\nsynthetic",
			}
			if s.sev == "critical" || s.sev == "high" {
				f.OOBConfirmed = level != VulnLevelPassive
			}
			cb.emitFinding(f)
			n++
		}
		if level == VulnLevelAggressive {
			np, _ := normalizePath("/search")
			cb.emitFinding(Finding{
				Fingerprint: findingFingerprint("sqli-error-based", h, np, "param:q"),
				TemplateID:  "sqli-error-based", Name: "SQL Injection (error-based)",
				Severity: "critical", Engine: "nuclei-dast", TemplateVersion: "v10.4.8",
				Tags: []string{"synthetic", "injection", "sqli"},
				Host: h, MatchedAt: "https://" + h + "/search?q=1%27", NormalizedPath: np,
				CWE: []string{"cwe-89"}, CVSSScore: 9.8, Level: VulnLevelAggressive,
				Extracted: []string{"You have an error in your SQL syntax"}, InScope: true,
			})
			n++
		}
	}
	cb.log("INFO", fmt.Sprintf("vulnerability scan — %d synthetic finding(s) (%s level)", n, level))
	return n
}

func tld(h string) string {
	if i := lastDot(h); i >= 0 {
		return h[i+1:]
	}
	return h
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}
