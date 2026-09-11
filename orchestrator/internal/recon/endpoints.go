package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/scope"
	"github.com/argus-platform/orchestrator/internal/ssrf"
)

// runEndpointDiscovery is Phase 7: crawl (katana) + historical URLs (gau) +
// well-known probes (robots / sitemap / OpenAPI / GraphQL), all normalized and
// route-templated, only emitting in-scope endpoints.
func runEndpointDiscovery(
	ctx context.Context, r plugin.Runner, eng *scope.Engine, guard *ssrf.Guard,
	dir string, aliveHosts []string, aliveBase map[string]string, knownHosts map[string]bool, opts Options, cb Callbacks,
) int {
	// gau returns a lot of malformed / historical hostnames (URL-encoding
	// artifacts, dead vhosts). Only keep endpoints whose host is a root or a
	// host we actually discovered in phases 1-5.
	roots := map[string]bool{}
	for _, x := range opts.Roots {
		roots[normHost(x)] = true
	}
	hostOK := func(h string) bool {
		h = normHost(h)
		return roots[h] || knownHosts[h]
	}
	// Distinct-endpoint cap — a historical-URL source can return tens of
	// thousands of URLs that collapse to far fewer structural signatures, but
	// still bound the total to keep ingestion sane.
	capN := opts.MaxTargets * 3
	if capN <= 0 {
		capN = 6000
	}
	seen := map[string]bool{}
	capped := false
	emit := func(ep Endpoint) {
		if !ep.InScope || capped || !hostOK(ep.Host) {
			return
		}
		key := ep.Method + " " + ep.NormalizedURL
		if seen[key] {
			return
		}
		if len(seen) >= capN {
			if !capped {
				cb.log("WARNING", fmt.Sprintf("endpoint discovery hit the %d distinct-endpoint cap", capN))
			}
			capped = true
			return
		}
		seen[key] = true
		cb.emitEndpoint(ep)
	}

	// gau — historical URLs for the roots
	if urls, err := gauFetch(ctx, r, opts.Roots, opts.RequestsPerSecond); err != nil {
		cb.log("WARNING", "gau: "+err.Error())
	} else {
		before := len(seen)
		for _, u := range urls {
			if ep, ok := makeEndpoint(u, "GET", eng, "gau"); ok {
				emit(ep)
			}
		}
		cb.log("INFO", fmt.Sprintf("gau: %d URL(s) → %d new distinct endpoint(s)", len(urls), len(seen)-before))
	}

	// katana — crawl alive in-scope hosts (bounded; a wildcard zone can make
	// hundreds of "hosts" that are all the same site)
	if len(aliveHosts) > 0 {
		crawlHosts := aliveHosts
		if len(crawlHosts) > 30 {
			crawlHosts = crawlHosts[:30]
			cb.log("WARNING", fmt.Sprintf("crawling the first 30 of %d alive hosts", len(aliveHosts)))
		}
		crawlURLs := make([]string, 0, len(crawlHosts))
		for _, h := range crawlHosts {
			crawlURLs = append(crawlURLs, baseURLFor(h, aliveBase))
		}
		if rows, err := katanaCrawl(ctx, r, dir, crawlURLs, 2, opts.RequestsPerSecond); err != nil {
			cb.log("WARNING", "katana: "+err.Error())
		} else {
			for _, row := range rows {
				if ep, ok := makeEndpoint(row.Request.Endpoint, row.Request.Method, eng, "katana"); ok {
					ep.StatusCode = row.Response.StatusCode
					ep.ContentType = row.Response.ContentType
					emit(ep)
				}
			}
			cb.log("INFO", fmt.Sprintf("katana: %d crawl result(s)", len(rows)))
		}
	}

	// well-known probes
	he := httpengine.New(eng, guard, httpengine.Options{
		RequestsPerSecond: opts.RequestsPerSecond, TimeoutSeconds: 10,
	})
	wk := probeWellKnown(ctx, he, eng, aliveHosts, aliveBase, Callbacks{
		Log: cb.Log, Cancelled: cb.Cancelled, Endpoint: func(ep Endpoint) { emit(ep) },
	})
	cb.log("INFO", fmt.Sprintf("well-known probes: %d endpoint(s)", wk))

	return len(seen)
}

// PhaseEndpoints is the Phase 7 key.
const PhaseEndpoints = "url_endpoint_discovery"

// Endpoint is a discovered URL/route emitted as an "endpoint" event. The
// gateway deduplicates on (method, normalized_url).
type Endpoint struct {
	Method            string   `json:"method"`
	Scheme            string   `json:"scheme"`
	Host              string   `json:"host"`
	Path              string   `json:"path"`
	NormalizedURL     string   `json:"normalized_url"`
	SampleURL         string   `json:"sample_url"`
	QueryKeys         []string `json:"query_keys"`
	Params            []Param  `json:"params"`
	StatusCode        int      `json:"status_code,omitempty"`
	ContentType       string   `json:"content_type,omitempty"`
	ContentLength     int      `json:"content_length,omitempty"`
	Sensitivity       string   `json:"sensitivity,omitempty"`
	SensitivityReason string   `json:"sensitivity_reason,omitempty"`
	InScope           bool     `json:"in_scope"`
	Tags              []string `json:"tags,omitempty"`
	Sources           []string `json:"sources"`
}

type Param struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // string | int | uuid | token | bool
	In   string `json:"in"`   // query | path
}

// ── URL normalization / route templating ──────────────────────────────────

var (
	reUUID   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHex    = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reInt    = regexp.MustCompile(`^\d+$`)
	reToken  = regexp.MustCompile(`^[A-Za-z0-9._~+/\-]{20,}={0,2}$`)
	reMD5ish = regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)
)

func classifySegment(seg string) (string, bool) {
	switch {
	case reUUID.MatchString(seg):
		return "{uuid}", true
	case reMD5ish.MatchString(seg):
		return "{hash}", true
	case reInt.MatchString(seg) && len(seg) >= 1:
		return "{id}", true
	case reHex.MatchString(seg):
		return "{hex}", true
	case reToken.MatchString(seg) && !strings.Contains(seg, "."):
		return "{token}", true
	}
	return seg, false
}

// normalizePath templates dynamic segments and returns (normalized, pathParams).
func normalizePath(p string) (string, []Param) {
	if p == "" {
		p = "/"
	}
	segs := strings.Split(p, "/")
	var params []Param
	for i, s := range segs {
		if s == "" {
			continue
		}
		if tmpl, dyn := classifySegment(s); dyn {
			segs[i] = tmpl
			params = append(params, Param{Name: strings.Trim(tmpl, "{}"), Kind: kindOf(tmpl), In: "path"})
		}
	}
	out := strings.Join(segs, "/")
	if out == "" {
		out = "/"
	}
	return out, params
}

func kindOf(tmpl string) string {
	switch tmpl {
	case "{id}":
		return "int"
	case "{uuid}":
		return "uuid"
	case "{token}", "{hash}", "{hex}":
		return "token"
	}
	return "string"
}

func paramKind(v string) string {
	switch {
	case v == "true" || v == "false":
		return "bool"
	case reInt.MatchString(v):
		return "int"
	case reUUID.MatchString(v):
		return "uuid"
	case reToken.MatchString(v):
		return "token"
	}
	return "string"
}

// makeEndpoint turns a raw URL (+ optional method) into a normalized Endpoint.
func makeEndpoint(raw, method string, eng *scope.Engine, source string) (Endpoint, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Endpoint{}, false
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if method == "" {
		method = "GET"
	}
	host := normHost(u.Hostname())
	normPath, pathParams := normalizePath(u.Path)

	var qk []string
	params := pathParams
	for k, vs := range u.Query() {
		qk = append(qk, k)
		v := ""
		if len(vs) > 0 {
			v = vs[0]
		}
		params = append(params, Param{Name: k, Kind: paramKind(v), In: "query"})
	}
	sort.Strings(qk)

	norm := host + normPath
	if len(qk) > 0 {
		norm += "?" + strings.Join(qk, "&")
	}

	d := eng.Evaluate(scope.Target{Host: host, Path: u.Path})
	return Endpoint{
		Method: strings.ToUpper(method), Scheme: u.Scheme, Host: host, Path: u.Path,
		NormalizedURL: norm, SampleURL: u.String(), QueryKeys: qk, Params: params,
		InScope: d.Allowed, Tags: endpointTags(u.Path), Sources: []string{source},
	}, true
}

func endpointTags(p string) []string {
	lp := strings.ToLower(p)
	var tags []string
	add := func(t string) { tags = append(tags, t) }
	switch {
	case strings.Contains(lp, "swagger"), strings.Contains(lp, "openapi"), strings.Contains(lp, "api-docs"):
		add("swagger")
	}
	if strings.Contains(lp, "graphql") {
		add("graphql")
	}
	if strings.HasSuffix(lp, ".js") || strings.HasSuffix(lp, ".mjs") {
		add("js")
	}
	if strings.Contains(lp, "/api/") || strings.HasPrefix(lp, "/api") || strings.Contains(lp, "/v1/") || strings.Contains(lp, "/v2/") {
		add("api")
	}
	if strings.Contains(lp, "admin") || strings.Contains(lp, "internal") || strings.Contains(lp, "dashboard") {
		add("admin")
	}
	if strings.Contains(lp, ".json") {
		add("json")
	}
	return tags
}

// ── katana adapter ────────────────────────────────────────────────────────

type katanaRow struct {
	Request struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"`
	} `json:"request"`
	Response struct {
		StatusCode  int    `json:"status_code"`
		ContentType string `json:"content_type"`
	} `json:"response"`
}

func katanaCrawl(ctx context.Context, r plugin.Runner, dir string, urls []string, depth, rps int) ([]katanaRow, error) {
	path, err := r.Look("katana")
	if err != nil {
		return nil, err
	}
	lf, err := writeList(dir, "crawl.txt", urls)
	if err != nil {
		return nil, err
	}
	argv := []string{
		path, "-list", lf, "-jsonl", "-silent", "-no-color",
		"-depth", itoa(depth), "-jc",
		"-timeout", "10", "-c", "5",
	}
	if rps > 0 {
		argv = append(argv, "-rate-limit", itoa(rps))
	}
	out, _, err := r.Exec(ctx, argv)
	if err != nil {
		return nil, err
	}
	var rows []katanaRow
	for _, ln := range jsonLines(out) {
		var row katanaRow
		if json.Unmarshal(ln, &row) == nil && row.Request.Endpoint != "" {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// ── gau adapter ───────────────────────────────────────────────────────────

func gauFetch(ctx context.Context, r plugin.Runner, roots []string, rps int) ([]string, error) {
	path, err := r.Look("gau")
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, root := range roots {
		argv := []string{path, "--subs", "--threads", "3", root}
		out, _, err := r.Exec(ctx, argv)
		if err != nil {
			return urls, err
		}
		for _, ln := range strings.Split(out, "\n") {
			if ln = strings.TrimSpace(ln); strings.HasPrefix(ln, "http") {
				urls = append(urls, ln)
			}
		}
	}
	return urls, nil
}

// ── well-known probes (robots / sitemap / openapi / graphql) ──────────────

var wellKnown = []struct {
	path string
	tag  string
}{
	{"/robots.txt", "robots"},
	{"/sitemap.xml", "sitemap"},
	{"/swagger.json", "swagger"},
	{"/openapi.json", "swagger"},
	{"/api-docs", "swagger"},
	{"/v2/api-docs", "swagger"},
	{"/swagger/v1/swagger.json", "swagger"},
	{"/.well-known/openid-configuration", "oidc"},
	{"/graphql", "graphql"},
	{"/graphiql", "graphql"},
}

var reHrefURL = regexp.MustCompile(`https?://[^\s"'<>)]+`)
var reSitemapLoc = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

func probeWellKnown(ctx context.Context, he *httpengine.Engine, eng *scope.Engine, aliveHosts []string, aliveBase map[string]string, cb Callbacks) int {
	n := 0
	for _, host := range aliveHosts {
		if cb.cancelled() {
			return n
		}
		base := baseURLFor(host, aliveBase)
		for _, wk := range wellKnown {
			u := base + wk.path
			resp, err := he.Get(ctx, u)
			if err != nil || resp.StatusCode >= 400 {
				continue
			}
			if ep, ok := makeEndpoint(u, "GET", eng, "well-known"); ok {
				ep.StatusCode = resp.StatusCode
				ep.ContentType = resp.Header.Get("Content-Type")
				ep.Tags = appendUniq(ep.Tags, wk.tag)
				cb.emitEndpoint(ep)
				n++
			}
			// extract nested URLs from robots/sitemap
			body := string(resp.Body)
			var links []string
			if wk.tag == "sitemap" {
				for _, m := range reSitemapLoc.FindAllStringSubmatch(body, 200) {
					links = append(links, m[1])
				}
			} else if wk.tag == "robots" {
				for _, ln := range strings.Split(body, "\n") {
					if p, ok := strings.CutPrefix(strings.TrimSpace(ln), "Disallow:"); ok {
						p = strings.TrimSpace(p)
						if p != "" && p != "/" {
							links = append(links, base+p)
						}
					}
					if p, ok := strings.CutPrefix(strings.TrimSpace(ln), "Sitemap:"); ok {
						links = append(links, strings.TrimSpace(p))
					}
				}
			} else if strings.Contains(resp.Header.Get("Content-Type"), "json") {
				for _, m := range reHrefURL.FindAllString(body, 500) {
					links = append(links, m)
				}
			}
			for _, l := range links {
				if ep, ok := makeEndpoint(l, "GET", eng, wk.tag); ok && ep.InScope {
					cb.emitEndpoint(ep)
					n++
				}
			}
		}
	}
	return n
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
