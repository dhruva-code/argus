package recon

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/scope"
)

// PhaseJSAnalysis is the Phase 8 key.
const PhaseJSAnalysis = "js_analysis_secrets"

var (
	reAbsURL       = regexp.MustCompile(`https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[a-zA-Z0-9/_\-.~%?=&#+]*)?`)
	rePathLiteral  = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d|graphql|internal|admin|auth|oauth|rest|rpc|user|users|account|config|\.well-known)[a-zA-Z0-9/_\-.{}$:]*)["'` + "`" + `]`)
	reSourceMap    = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
	reS3Bucket     = regexp.MustCompile(`(?:https?://)?([a-z0-9.\-]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com`)
	reInternalHost = regexp.MustCompile(`\b((?:[a-z0-9\-]+\.)+(?:internal|intranet|corp|local|lan|test|dev|staging))\b`)
)

// runJSAnalysis fetches every discovered JS URL, scans it for secrets
// (trufflehog + gitleaks + custom), and extracts endpoints / domains /
// source-map references. New in-scope hosts are re-checked against scope.
func runJSAnalysis(
	ctx context.Context, r plugin.Runner, he *httpengine.Engine, eng *scope.Engine,
	dir string, jsURLs []string, maxBytes int, cb Callbacks,
) (int, int) {
	jsURLs = uniqSorted2(jsURLs)
	secretsN, endpointsN := 0, 0
	scanned := 0

	// Collect every JS body into one directory, then run the secret scanners
	// once over the whole set (per-file invocation is far too slow).
	scanDir, _ := os.MkdirTemp(dir, "js-*")
	defer os.RemoveAll(scanDir)
	fileToURL := map[string]string{}
	blocked := 0

	for i, u := range jsURLs {
		if cb.cancelled() {
			break
		}
		resp, err := he.Get(ctx, u)
		if err != nil {
			if httpengine.IsBlocked(err) {
				blocked++
			}
			continue
		}
		if resp.StatusCode >= 400 || len(resp.Body) == 0 {
			continue
		}
		scanned++
		body := string(resp.Body)
		if maxBytes > 0 && len(body) > maxBytes {
			body = body[:maxBytes]
		}

		fname := fmt.Sprintf("%04d.js", i)
		if os.WriteFile(scanDir+"/"+fname, []byte(body), 0o600) == nil {
			fileToURL[fname] = u
		}
		for _, s := range customScan(body, "js:"+u) {
			s.SourceKind = "js"
			s.Source = u
			cb.emitSecret(s)
			secretsN++
		}

		// endpoints referenced in the JS
		for _, m := range rePathLiteral.FindAllStringSubmatch(body, 400) {
			origin := originOf(u)
			if origin == "" {
				continue
			}
			if ep, ok := makeEndpoint(origin+m[1], "GET", eng, "js"); ok && ep.InScope {
				ep.Tags = appendUniq(ep.Tags, "js-ref")
				cb.emitEndpoint(ep)
				endpointsN++
			}
		}
		for _, abs := range reAbsURL.FindAllString(body, 400) {
			if ep, ok := makeEndpoint(abs, "GET", eng, "js"); ok && ep.InScope {
				ep.Tags = appendUniq(ep.Tags, "js-ref")
				cb.emitEndpoint(ep)
				endpointsN++
			}
		}

		// domains / internal hostnames — recorded as assets, scope-tagged
		domains := map[string]bool{}
		for _, m := range reAbsURL.FindAllString(body, 400) {
			if h := hostOf(m); h != "" {
				domains[h] = true
			}
		}
		for _, m := range reInternalHost.FindAllStringSubmatch(body, 100) {
			domains[strings.ToLower(m[1])] = true
		}
		for _, m := range reS3Bucket.FindAllStringSubmatch(body, 50) {
			cb.Asset(Asset{
				Type: TypeDomain, Value: m[1] + ".s3.amazonaws.com", Status: StatusUnknown,
				Sources: []string{"js"}, Tags: []string{"s3-bucket", "cloud-ref"},
			})
		}
		for h := range domains {
			d := eng.Evaluate(scope.Target{Host: h})
			cb.Asset(Asset{
				Type: subOrDomain(h, nil), Value: h, Status: StatusUnknown,
				InScope: d.Allowed, ScopeReason: d.Reason, Sources: []string{"js"},
				Tags: append([]string{"js-ref"}, scopeTags(d.Allowed)...),
			})
		}

		// source maps
		for _, m := range reSourceMap.FindAllStringSubmatch(body, 5) {
			smURL := m[1]
			if !strings.HasPrefix(smURL, "http") {
				smURL = originOf(u) + resolveRel(pathOf(u), smURL)
			}
			if ep, ok := makeEndpoint(smURL, "GET", eng, "js"); ok && ep.InScope {
				ep.Tags = appendUniq(ep.Tags, "source-map")
				cb.emitEndpoint(ep)
				endpointsN++
			}
		}
	}

	// One trufflehog + gitleaks pass over the whole directory.
	if scanned > 0 && !cb.cancelled() {
		for _, s := range trufflehogFile(ctx, r, scanDir, "js") {
			s.SourceKind = "js"
			s.Source = jsSourceFromLoc(s.Location, fileToURL)
			s.Location = s.Source
			cb.emitSecret(s)
			secretsN++
		}
		for _, s := range gitleaksDir(ctx, r, scanDir, "js") {
			s.SourceKind = "js"
			s.Source = jsSourceFromLoc(s.Location, fileToURL)
			s.Location = s.Source
			cb.emitSecret(s)
			secretsN++
		}
	}

	if blocked > 0 {
		cb.log("WARNING", fmt.Sprintf("%d JS URL(s) skipped (scope/SSRF policy)", blocked))
	}
	cb.log("INFO", fmt.Sprintf("JavaScript analysis — fetched %d file(s), %d secret candidate(s), %d referenced endpoint(s)",
		scanned, secretsN, endpointsN))
	return secretsN, endpointsN
}

// jsSourceFromLoc maps a "js/<NNNN>.js:line" location back to the real URL.
func jsSourceFromLoc(loc string, fileToURL map[string]string) string {
	base := loc
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	line := ""
	if i := strings.Index(base, ":"); i >= 0 {
		line = base[i:]
		base = base[:i]
	}
	if u, ok := fileToURL[base]; ok {
		return u + line
	}
	return loc
}

// discoverJSURLs collects JS file URLs: gau history filtered to *.js, plus a
// focused katana crawl of the alive hosts. aliveBases are full base URLs
// ("http://h" / "https://h") so the crawl and the fetch use the scheme the
// host actually serves on.
func discoverJSURLs(ctx context.Context, r plugin.Runner, dir string, aliveBases []string, opts Options) []string {
	// dedup by (host + path), dropping cache-buster query params so 400 copies
	// of the same file collapse to one. The scheme of the first sighting wins.
	set := map[string]string{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		h := hostOf(raw)
		p := pathOf(raw)
		if h == "" || !strings.Contains(p, ".js") {
			return
		}
		key := h + strings.SplitN(p, "?", 2)[0]
		if _, seen := set[key]; !seen {
			set[key] = schemeOf(raw) + "://" + h + strings.SplitN(p, "?", 2)[0]
		}
	}
	// katana first (targeted, fast); gau only tops it up.
	if len(aliveBases) > 0 {
		hs := aliveBases
		if len(hs) > 15 {
			hs = hs[:15]
		}
		if rows, err := katanaCrawl(ctx, r, dir, hs, 2, opts.RequestsPerSecond); err == nil {
			for _, row := range rows {
				add(row.Request.Endpoint)
			}
		}
	}
	if len(set) < 100 {
		if urls, err := gauFetch(ctx, r, opts.Roots, opts.RequestsPerSecond); err == nil {
			for _, u := range urls {
				add(u)
			}
		}
	}
	out := make([]string, 0, len(set))
	for _, u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// ── helpers ────────────────────────────────────────────────────────────────

func hostOf(rawurl string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(rawurl, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return normHost(s)
}

func schemeOf(rawurl string) string {
	if strings.HasPrefix(rawurl, "http://") {
		return "http"
	}
	return "https"
}

// originOf returns "scheme://host" for a raw URL, or "" if it has no host.
func originOf(rawurl string) string {
	h := hostOf(rawurl)
	if h == "" {
		return ""
	}
	return schemeOf(rawurl) + "://" + h
}

func pathOf(rawurl string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(rawurl, "https://"), "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		return s[i:]
	}
	return "/"
}

func resolveRel(base, rel string) string {
	if strings.HasPrefix(rel, "/") {
		return rel
	}
	dir := base
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		dir = dir[:i+1]
	}
	return dir + rel
}

func uniqSorted2(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		x = strings.TrimSpace(x)
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
