package recon

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/argus-platform/orchestrator/internal/httpengine"
	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/scope"
	"github.com/argus-platform/orchestrator/internal/ssrf"
)

// Options configure a scan run.
type Options struct {
	Roots             []string // root domains extracted from scope
	Phases            []string // enabled phase keys
	RequestsPerSecond int
	DNSPerSecond      int
	MaxTargets        int
	BruteWords        []string // optional permutation prefixes for active enum
	WordlistPath      string   // ffuf wordlist for directory discovery
	GitHubToken       string   // optional, for source-code intelligence
	GitHubOrgs        []string // optional explicit org names to enumerate
	// M5 — ports & vulnerability scanning
	PortSpec           string // "" | "top-100" | "top-1000" | "22,80,443,..."
	ServiceDetection   bool   // run nmap -sV on discovered ports
	VulnLevel          string // passive | safe_verify | manual_review
	VulnScanEndpoints  bool   // also feed discovered endpoint URLs to nuclei
	MaxVulnTargets     int    // cap on nuclei targets (default 15)
	NucleiTemplatesDir string
	// Injection Testing Engine (§1-13)
	MaxInjectionParams int    // cap on distinct parameters tested
	InjectionSSRF      bool   // §7 — only with the explicit advanced-testing policy
	OASTCollectorURL   string // public collector base; "" disables SSRF/RFI verification
	OASTStatusURL      string // gateway URL the orchestrator can reach, for polling
	OASTInternalToken  string
	ProjectID          string
	BrowserBinary      string // resolved Node binary for headless XSS verification; "" disables it
	AuthHeaderName     string // §17 Authentication Profile, attached to every injection test
	AuthHeaderValue    string
	maxResponseBytes   int
}

// Result is a small summary returned to the caller for the final status.
type Result struct {
	Discovered      int
	InScope         int
	Resolved        int
	Alive           int
	Endpoints       int
	Secrets         int
	SensitivePaths  int
	Repos           int
	Ports           int
	Findings        int
	InjectionPoints int
	Phases          []string
}

// Synthetic reports whether the deterministic offline surface is in use.
func Synthetic() bool { return os.Getenv("ARGUS_SYNTHETIC_RECON") == "true" }

func has(phases []string, p string) bool {
	for _, x := range phases {
		if x == p {
			return true
		}
	}
	return false
}

// Run walks the enabled phases. It is resumable-friendly: each phase checkpoints
// its output, and re-emitting an asset is idempotent on the gateway side.
func Run(
	ctx context.Context,
	eng *scope.Engine,
	guard *ssrf.Guard,
	runner plugin.Runner,
	opts Options,
	cb Callbacks,
) (Result, error) {
	res := Result{Phases: opts.Phases}
	synth := Synthetic()
	if synth {
		cb.log("WARNING", "ARGUS_SYNTHETIC_RECON=true — using the deterministic offline surface, no tools run")
	}

	// Record every in-scope endpoint URL that carries parameters, so the
	// aggressive vuln level can fuzz them for injection.
	var paramURLs []string
	userEndpoint := cb.Endpoint
	cb.Endpoint = func(ep Endpoint) {
		if ep.InScope && len(ep.QueryKeys) > 0 && ep.SampleURL != "" {
			paramURLs = append(paramURLs, ep.SampleURL)
		}
		if userEndpoint != nil {
			userEndpoint(ep)
		}
	}

	dir, err := os.MkdirTemp("", "argus-recon-*")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(dir)

	// hosts: subdomain -> ordered set of sources
	hosts := map[string]map[string]bool{}
	addHost := func(h string, sources ...string) {
		h = normHost(h)
		if h == "" {
			return
		}
		if hosts[h] == nil {
			hosts[h] = map[string]bool{}
		}
		for _, s := range sources {
			hosts[h][s] = true
		}
	}
	for _, r := range opts.Roots {
		addHost(r, "scope")
	}

	scopeOf := func(h string) scope.Decision {
		return eng.Evaluate(scope.Target{Host: h})
	}

	// ── PHASE 1: passive subdomain enumeration ───────────────────────────
	if has(opts.Phases, PhasePassiveEnum) {
		cb.log("INFO", fmt.Sprintf("PHASE passive_subdomain_enum — %d root domain(s)", len(opts.Roots)))
		if synth {
			for h, srcs := range syntheticSubdomains(opts.Roots) {
				addHost(h, srcs...)
			}
		} else {
			sf, err := subfinderEnum(ctx, runner, dir, opts.Roots)
			if err != nil {
				cb.log("ERROR", "subfinder: "+err.Error())
			} else {
				for h, srcs := range sf {
					for s := range srcs {
						addHost(h, s)
					}
				}
				cb.log("INFO", fmt.Sprintf("subfinder: %d host(s)", len(sf)))
			}
			if af, err := assetfinderEnum(ctx, runner, opts.Roots); err != nil {
				cb.log("WARNING", "assetfinder: "+err.Error())
			} else {
				for h := range af {
					addHost(h, "assetfinder")
				}
				cb.log("INFO", fmt.Sprintf("assetfinder: %d host(s)", len(af)))
			}
		}
		// Accuracy over volume: a passive source can return tens of thousands of
		// junk certificate entries for a common name. Cap to max_targets,
		// keeping the roots and preferring in-scope hosts.
		if cap := opts.MaxTargets; cap > 0 && len(hosts) > cap {
			hosts = capHosts(hosts, opts.Roots, eng, cap)
			cb.log("WARNING", fmt.Sprintf(
				"passive enum returned more than max_targets=%d hosts — capped (in-scope hosts kept first)", cap))
		}

		emitHosts(eng, opts.Roots, hosts, StatusUnknown, cb)
		cb.Checkpoint(PhasePassiveEnum, map[string]any{"hosts": len(hosts)})
		if cb.cancelled() {
			return res, nil
		}
	}

	// ── PHASE 2: active enumeration + resolution ─────────────────────────
	resolved := map[string]resolvedHost{}
	aliveSet := map[string]bool{}
	if has(opts.Phases, PhaseActiveEnum) {
		cb.log("INFO", "PHASE active_subdomain_enum — resolution"+bruteNote(opts.BruteWords))

		// permutation bruteforce for in-scope roots only
		if len(opts.BruteWords) > 0 {
			for _, root := range opts.Roots {
				for _, w := range opts.BruteWords {
					cand := w + "." + root
					if scopeOf(cand).Allowed {
						addHost(cand, "bruteforce")
					}
				}
			}
		}

		all := sortedKeys(hosts)
		if opts.MaxTargets > 0 && len(all) > opts.MaxTargets {
			cb.log("WARNING", fmt.Sprintf("capping resolution at max_targets=%d (had %d)", opts.MaxTargets, len(all)))
			all = all[:opts.MaxTargets]
		}

		var rows []dnsxRow
		if synth {
			rows = syntheticResolve(all)
		} else if len(all) > 0 {
			rows, err = dnsxResolve(ctx, runner, dir, all, opts.DNSPerSecond)
			if err != nil {
				cb.log("ERROR", "dnsx: "+err.Error())
			}
		}

		// wildcard detection per root
		wildcards := detectWildcards(ctx, runner, dir, opts.Roots, synth)
		for w := range wildcards {
			cb.log("WARNING", "wildcard DNS detected for *."+w+" — brute results de-prioritized")
		}

		for _, row := range rows {
			ips := append(append([]string{}, row.A...), row.AAAA...)
			rh := resolvedHost{host: row.Host, ips: ips, cname: first(row.CNAME)}
			if isWildcarded(row.Host, wildcards) && hosts[row.Host]["bruteforce"] && len(hosts[row.Host]) == 1 {
				continue // unresolved brute guess behind a wildcard
			}
			resolved[row.Host] = rh
		}
		res.Resolved = len(resolved)
		emitResolved(eng, opts.Roots, resolved, hosts, wildcards, cb)
		cb.Checkpoint(PhaseActiveEnum, map[string]any{"resolved": len(resolved)})
		if cb.cancelled() {
			return res, nil
		}
	}

	// host -> base URL ("http://h" / "https://h") of the alive service, so the
	// later active phases probe the scheme httpx actually found rather than
	// assuming https (many real targets are http-only).
	aliveBase := map[string]string{}

	// ── PHASE 5: merge / resolve / alive-host detection ──────────────────
	if has(opts.Phases, PhaseMergeAlive) {
		// If phase 2 was skipped, resolve here.
		if len(resolved) == 0 {
			all := sortedKeys(hosts)
			var rows []dnsxRow
			if synth {
				rows = syntheticResolve(all)
			} else if len(all) > 0 {
				rows, _ = dnsxResolve(ctx, runner, dir, all, opts.DNSPerSecond)
			}
			for _, row := range rows {
				ips := append(append([]string{}, row.A...), row.AAAA...)
				resolved[row.Host] = resolvedHost{host: row.Host, ips: ips, cname: first(row.CNAME)}
			}
			emitResolved(eng, opts.Roots, resolved, hosts, map[string]bool{}, cb)
		}
		res.Resolved = len(resolved)

		// Only probe hosts that are in scope AND whose IPs pass the SSRF guard.
		var probe []string
		for h, rh := range resolved {
			d := scopeOf(h)
			if !d.Allowed {
				continue
			}
			if !synth && !ipsAllowed(guard, rh.ips) {
				cb.log("WARNING", h+": resolved to a blocked address, skipping probe")
				continue
			}
			probe = append(probe, h)
		}
		sort.Strings(probe)
		cb.log("INFO", fmt.Sprintf("PHASE merge_resolve_alive — probing %d in-scope host(s)", len(probe)))

		var rows []httpxRow
		if synth {
			rows = syntheticHTTP(probe)
		} else if len(probe) > 0 {
			rows, err = httpxProbe(ctx, runner, dir, probe, opts.RequestsPerSecond)
			if err != nil {
				cb.log("ERROR", "httpx: "+err.Error())
			}
		}

		for _, row := range rows {
			in := row.Input
			if in == "" {
				in = normHost(row.URL)
			}
			in = normHost(in)
			aliveSet[in] = true
			aliveBase[in] = aliveBaseURL(row, in)
			emitAlive(in, opts.Roots, row, hosts, cb)
		}
		// hosts that resolved but returned nothing → dead
		for _, h := range probe {
			if !aliveSet[h] {
				cb.Asset(Asset{Type: subOrDomain(h, opts.Roots), Value: h, Status: StatusDead,
					InScope: true, Sources: sourceList(hosts[h])})
			}
		}
		res.Alive = len(aliveSet)
		cb.Checkpoint(PhaseMergeAlive, map[string]any{"alive": len(aliveSet)})
	}

	// Shared inputs for the M3 phases: IPs that an in-scope host resolves to,
	// and the hostnames pointing at each.
	inScopeIP := func(ip string) bool { return eng.Evaluate(scope.Target{IP: ip}).Allowed }
	ipHosts := map[string][]string{}
	relevantIPs := map[string]bool{}
	for h, rh := range resolved {
		if !scopeOf(h).Allowed {
			continue
		}
		for _, ip := range rh.ips {
			ipHosts[ip] = append(ipHosts[ip], h)
			relevantIPs[ip] = true
		}
	}

	// ip -> ASN org, filled by infra mapping, consumed by WAF/CDN origin intel.
	ipASNOrg := map[string]string{}

	// ── PHASE 3: infrastructure mapping ─────────────────────────────────
	if has(opts.Phases, PhaseInfraMap) && !cb.cancelled() {
		cb.log("INFO", fmt.Sprintf("PHASE infrastructure_mapping — %d IP(s)", len(relevantIPs)))
		if synth {
			runSyntheticInfra(sortedKeys(relevantIPs), ipASNOrg, cb)
		} else {
			runInfraMapping(ctx, sortedKeys(relevantIPs), ipASNOrg, cb)
		}
		cb.Checkpoint(PhaseInfraMap, map[string]any{"ips": len(relevantIPs)})
	}

	// ── PHASE 4: WAF / CDN fingerprint & origin-IP intel ───────────────
	if has(opts.Phases, PhaseWAFCDN) && !cb.cancelled() {
		if synth {
			res.Findings += runSyntheticWAFCDN(aliveBase, opts.Roots, cb)
		} else {
			he := httpengine.New(eng, guard, httpengine.Options{
				RequestsPerSecond: opts.RequestsPerSecond, TimeoutSeconds: 10,
				MaxResponseBytes: 128 << 10,
			})
			res.Findings += runWAFCDNIntel(ctx, he, eng, aliveBase, resolved, ipASNOrg, opts.Roots, cb)
		}
		cb.Checkpoint(PhaseWAFCDN, map[string]any{"fronted": len(aliveBase)})
	}

	// ── PHASE 6: virtual-host enumeration ──────────────────────────────
	if has(opts.Phases, PhaseVHost) && !cb.cancelled() && !synth {
		he := httpengine.New(eng, guard, httpengine.Options{
			RequestsPerSecond: opts.RequestsPerSecond, TimeoutSeconds: 10,
		})
		runVHostEnum(ctx, he, ipHosts, inScopeIP,
			func(h string) bool { return scopeOf(h).Allowed }, cb)
		cb.Checkpoint(PhaseVHost, map[string]any{"ips": len(ipHosts)})
	} else if has(opts.Phases, PhaseVHost) && synth {
		runSyntheticVHosts(ipHosts, cb)
	}

	// ── PHASE 7: URL & endpoint discovery ──────────────────────────────
	if has(opts.Phases, PhaseEndpoints) && !cb.cancelled() {
		alive := sortedKeys(aliveSet)
		cb.log("INFO", fmt.Sprintf("PHASE url_endpoint_discovery — %d alive host(s)", len(alive)))
		n := 0
		if synth {
			n = runSyntheticEndpoints(alive, opts.Roots, eng, cb)
		} else {
			// Only hosts that actually resolved — passive enum returns junk
			// CT entries (truncated / mangled names) that never resolve.
			known := map[string]bool{}
			for h := range resolved {
				known[h] = true
			}
			for h := range aliveSet {
				known[h] = true
			}
			n = runEndpointDiscovery(ctx, runner, eng, guard, dir, alive, aliveBase, known, opts, cb)
		}
		res.Endpoints = n
		cb.Checkpoint(PhaseEndpoints, map[string]any{"endpoints": n})
	}

	aliveList := sortedKeys(aliveSet)

	// Each expensive M4 phase gets its own wall-clock budget so a scan of a
	// large real target completes rather than running for hours.
	phaseCtx := func(minutes int) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, time.Duration(minutes)*time.Minute)
	}

	// ── PHASE 8: JavaScript analysis & secret extraction ───────────────
	if has(opts.Phases, PhaseJSAnalysis) && !cb.cancelled() {
		if synth {
			runSyntheticJS(aliveList, eng, cb)
		} else {
			pctx, cancel := phaseCtx(8)
			he := httpengine.New(eng, guard, httpengine.Options{
				RequestsPerSecond: opts.RequestsPerSecond, TimeoutSeconds: 12,
				MaxResponseBytes: int64(opts.MaxResponseBytes()) * 4,
			})
			jsURLs := discoverJSURLs(pctx, runner, dir, baseURLsFor(aliveList, aliveBase), opts)
			cb.log("INFO", fmt.Sprintf("PHASE js_analysis_secrets — %d JS file(s) to analyse", len(jsURLs)))
			sN, _ := runJSAnalysis(pctx, runner, he, eng, dir, jsURLs, opts.MaxResponseBytes()*4, cb)
			res.Secrets += sN
			cancel()
		}
		cb.Checkpoint(PhaseJSAnalysis, map[string]any{"secrets": res.Secrets})
	}

	// ── PHASE 9: directory & sensitive-file discovery ──────────────────
	if has(opts.Phases, PhaseDirDiscovery) && !cb.cancelled() {
		if synth {
			runSyntheticDirs(aliveList, eng, cb)
		} else {
			pctx, cancel := phaseCtx(10)
			res.SensitivePaths += runDirDiscovery(pctx, runner, eng, dir, aliveList, aliveBase, opts.WordlistPath, opts, cb)
			cancel()
		}
		cb.Checkpoint(PhaseDirDiscovery, map[string]any{"paths": res.SensitivePaths})
	}

	// ── PHASE 10: GitHub & source-code intelligence ────────────────────
	if has(opts.Phases, PhaseSourceIntel) && !cb.cancelled() {
		if synth {
			runSyntheticRepos(opts.Roots, cb)
		} else {
			pctx, cancel := phaseCtx(10)
			rN, sN := runSourceIntel(pctx, runner, eng, opts.Roots, opts, cb)
			res.Repos += rN
			res.Secrets += sN
			cancel()
		}
		cb.Checkpoint(PhaseSourceIntel, map[string]any{"repos": res.Repos})
	}

	// ── PHASE 11: port scan & service fingerprinting ──────────────────────
	if has(opts.Phases, PhasePortScan) && !cb.cancelled() {
		if synth {
			res.Ports += runSyntheticPorts(sortedKeys(relevantIPs), ipHosts, cb)
		} else {
			pctx, cancel := phaseCtx(12)
			res.Ports += runPortScan(pctx, runner, guard, eng, dir, sortedKeys(relevantIPs), ipHosts, opts, cb)
			cancel()
		}
		cb.Checkpoint(PhasePortScan, map[string]any{"ports": res.Ports})
	}

	// ── PHASE 12: automated vulnerability scanning ────────────────────────
	if has(opts.Phases, PhaseVulnScan) && !cb.cancelled() {
		level := opts.VulnLevel
		if level == "" {
			level = VulnLevelPassive
		}
		vt := baseURLsFor(aliveList, aliveBase)
		budget := 25
		if level == VulnLevelAggressive {
			budget = 40 // the DAST pass needs its own headroom
		}
		if synth {
			res.Findings += runSyntheticFindings(aliveList, level, eng, cb)
		} else {
			pctx, cancel := phaseCtx(budget)
			res.Findings += runVulnScan(pctx, runner, eng, dir, vt, uniqSorted2(paramURLs), level, opts, cb)
			cancel()
		}
		cb.Checkpoint(PhaseVulnScan, map[string]any{"findings": res.Findings})
	}

	// ── PHASE: dedicated Injection Testing Engine (§1-13) ─────────────────
	if has(opts.Phases, PhaseInjectionTesting) && !cb.cancelled() {
		if synth {
			pts, finds := runSyntheticInjection(aliveList, eng, cb)
			res.InjectionPoints += pts
			res.Findings += finds
		} else {
			pctx, cancel := phaseCtx(35)
			iopts := injectionOptions{
				MaxParams: opts.MaxInjectionParams, EnableSSRF: opts.InjectionSSRF,
				OASTCollectorURL: opts.OASTCollectorURL, OASTStatusURL: opts.OASTStatusURL,
				OASTInternalTok: opts.OASTInternalToken, ProjectID: opts.ProjectID,
				BrowserBinary:  opts.BrowserBinary,
				AuthHeaderName: opts.AuthHeaderName, AuthHeaderValue: opts.AuthHeaderValue,
			}
			pts, finds := runInjectionTesting(pctx, eng, guard, uniqSorted2(paramURLs), opts, iopts, cb)
			res.InjectionPoints += pts
			res.Findings += finds
			cancel()
		}
		cb.Checkpoint(PhaseInjectionTesting, map[string]any{"points": res.InjectionPoints, "findings": res.Findings})
	}

	res.Discovered = len(hosts)
	res.InScope = 0
	for h := range hosts {
		if scopeOf(h).Allowed {
			res.InScope++
		}
	}
	cb.log("INFO", fmt.Sprintf("recon complete — %d discovered, %d resolved, %d alive",
		res.Discovered, res.Resolved, res.Alive))
	return res, nil
}

type resolvedHost struct {
	host  string
	ips   []string
	cname string
}

// capHosts keeps the roots plus, up to n total, in-scope hosts first then the
// rest (deterministic by sorted name).
func capHosts(hosts map[string]map[string]bool, roots []string, eng *scope.Engine, n int) map[string]map[string]bool {
	rootSet := map[string]bool{}
	for _, r := range roots {
		rootSet[normHost(r)] = true
	}
	names := sortedKeys(hosts)
	sort.SliceStable(names, func(i, j int) bool {
		ai := rootSet[names[i]] || eng.Evaluate(scope.Target{Host: names[i]}).Allowed
		aj := rootSet[names[j]] || eng.Evaluate(scope.Target{Host: names[j]}).Allowed
		if ai != aj {
			return ai
		}
		return names[i] < names[j]
	})
	out := map[string]map[string]bool{}
	for i, name := range names {
		if i >= n && !rootSet[name] {
			continue
		}
		out[name] = hosts[name]
	}
	return out
}

func emitHosts(eng *scope.Engine, roots []string, hosts map[string]map[string]bool, status string, cb Callbacks) {
	for h, srcs := range hosts {
		if cb.cancelled() {
			return
		}
		d := eng.Evaluate(scope.Target{Host: h})
		cb.Asset(Asset{
			Type: subOrDomain(h, roots), Value: h, Status: status,
			InScope: d.Allowed, ScopeReason: d.Reason, Sources: sourceList(srcs),
			Tags: scopeTags(d.Allowed),
		})
	}
}

func emitResolved(eng *scope.Engine, roots []string, resolved map[string]resolvedHost, hosts map[string]map[string]bool, wildcards map[string]bool, cb Callbacks) {
	for h, rh := range resolved {
		if cb.cancelled() {
			return
		}
		d := eng.Evaluate(scope.Target{Host: h})
		a := Asset{
			Type: subOrDomain(h, roots), Value: h, Status: StatusResolved,
			InScope: d.Allowed, ScopeReason: d.Reason, Sources: sourceList(hosts[h]),
			IPAddresses: rh.ips, CNAME: rh.cname, IsWildcard: isWildcarded(h, wildcards),
			Tags: scopeTags(d.Allowed),
		}
		cb.Asset(a)
		for _, ip := range rh.ips {
			ipd := eng.Evaluate(scope.Target{IP: ip})
			cb.Asset(Asset{
				Type: TypeIP, Value: ip, Status: StatusResolved,
				InScope: ipd.Allowed, ScopeReason: ipd.Reason,
				Sources: []string{"dnsx"}, Tags: scopeTags(ipd.Allowed),
			})
			cb.Edge(Edge{SrcType: a.Type, SrcValue: h, DstType: TypeIP, DstValue: ip, Kind: EdgeResolvesTo})
		}
		if rh.cname != "" {
			cb.Edge(Edge{SrcType: a.Type, SrcValue: h, DstType: TypeDomain, DstValue: normHost(rh.cname), Kind: EdgeCnameTo})
		}
	}
}

func emitAlive(host string, roots []string, row httpxRow, hosts map[string]map[string]bool, cb Callbacks) {
	port := 0
	if row.Port != "" {
		port, _ = strconv.Atoi(row.Port)
	}
	tls := []string(nil)
	if row.TLS != nil {
		tls = row.TLS.SubjectAN
	}
	techs := row.Tech
	if row.CDN != "" {
		techs = append(techs, "CDN:"+row.CDN)
	}
	a := Asset{
		Type: subOrDomain(host, roots), Value: host, Status: StatusAlive, InScope: true,
		Sources:      sourceList(hosts[host]),
		HTTPStatus:   row.StatusCode,
		HTTPTitle:    trim(row.Title, 500),
		HTTPServer:   row.Webserver,
		HTTPScheme:   row.Scheme,
		HTTPPort:     port,
		ContentType:  row.ContentType,
		FinalURL:     row.Location,
		TLSNames:     tls,
		Technologies: dedupe(techs),
	}
	cb.Asset(a)
	if row.URL != "" {
		cb.Asset(Asset{Type: TypeURL, Value: row.URL, Status: StatusAlive, InScope: true,
			Sources: []string{"httpx"}, HTTPStatus: row.StatusCode})
		cb.Edge(Edge{SrcType: a.Type, SrcValue: host, DstType: TypeURL, DstValue: row.URL, Kind: EdgeHosts})
	}
	if row.Location != "" && row.Location != row.URL {
		cb.Edge(Edge{SrcType: TypeURL, SrcValue: row.URL, DstType: TypeURL, DstValue: row.Location, Kind: EdgeRedirectsTo})
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sourceList(m map[string]bool) []string {
	if m == nil {
		return nil
	}
	out := sortedKeys(m)
	return out
}

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func scopeTags(inScope bool) []string {
	if inScope {
		return nil
	}
	return []string{"out-of-scope"}
}

// subOrDomain classifies a hostname: a listed root (or a bare 2-label name) is a
// domain, anything deeper is a subdomain.
func subOrDomain(host string, roots []string) string {
	for _, r := range roots {
		if host == normHost(r) {
			return TypeDomain
		}
	}
	if strings.Count(host, ".") <= 1 {
		return TypeDomain
	}
	return TypeSubdomain
}

func bruteNote(w []string) string {
	if len(w) == 0 {
		return ""
	}
	return fmt.Sprintf(" + %d-prefix permutation bruteforce", len(w))
}

// aliveBaseURL derives "scheme://host" for a probed host from the httpx row,
// falling back to https when the row carries nothing usable.
func aliveBaseURL(row httpxRow, host string) string {
	if row.URL != "" {
		if u, err := url.Parse(row.URL); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
			return u.Scheme + "://" + u.Host
		}
	}
	sch := row.Scheme
	if sch != "http" && sch != "https" {
		sch = "https"
	}
	return sch + "://" + host
}

// baseURLsFor maps hostnames to their discovered base URL (or an https guess).
func baseURLsFor(hosts []string, aliveBase map[string]string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if b := aliveBase[h]; b != "" {
			out = append(out, b)
		} else {
			out = append(out, "https://"+h)
		}
	}
	return out
}

// baseURLFor returns the discovered base URL for a single host (or an https guess).
func baseURLFor(host string, aliveBase map[string]string) string {
	if b := aliveBase[host]; b != "" {
		return b
	}
	return "https://" + host
}

func ipsAllowed(guard *ssrf.Guard, ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if guard.CheckAddr(ip) != nil {
			return false
		}
	}
	return true
}

func isWildcarded(host string, wildcards map[string]bool) bool {
	for w := range wildcards {
		if host == w || strings.HasSuffix(host, "."+w) {
			return true
		}
	}
	return false
}

// detectWildcards resolves a guaranteed-nonexistent label under each root; if it
// answers, the zone has a wildcard record.
func detectWildcards(ctx context.Context, r plugin.Runner, dir string, roots []string, synth bool) map[string]bool {
	if synth || len(roots) == 0 {
		return map[string]bool{}
	}
	probes := make([]string, 0, len(roots))
	idx := map[string]string{}
	for _, root := range roots {
		p := "argus-wildcard-probe-zzq9x." + root
		probes = append(probes, p)
		idx[p] = root
	}
	rows, err := dnsxResolve(ctx, r, dir, probes, 0)
	if err != nil {
		return map[string]bool{}
	}
	wc := map[string]bool{}
	for _, row := range rows {
		if len(row.A) > 0 || len(row.AAAA) > 0 {
			if root, ok := idx[row.Host]; ok {
				wc[root] = true
			}
		}
	}
	return wc
}
