// Injection Testing Engine (§1-13 of the platform enhancement spec).
//
// Pipeline: endpoint discovery → parameter extraction → classification →
// baseline request → low-impact detection → response comparison → candidate →
// safe verification → evidence collection → confidence scoring → finding.
//
// The engine never sends destructive payloads (no DROP/DELETE/UNION dumps, no
// arbitrary file writes, no shell persistence, no exfiltration). It stops at
// the minimum evidence needed to prove a class of bug, and every request goes
// through the same scope + SSRF guard as every other phase.
package recon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/argus-platform/orchestrator/internal/httpengine"
	"github.com/argus-platform/orchestrator/internal/scope"
)

// PhaseInjectionTesting is the dedicated Injection Testing Engine phase.
const PhaseInjectionTesting = "injection_testing"

// ── vulnerability classes ───────────────────────────────────────────────

type InjClass string

const (
	ClassSQLi          InjClass = "sqli"
	ClassXSS           InjClass = "xss"
	ClassHTMLInjection InjClass = "html_injection"
	ClassCRLF          InjClass = "crlf"
	ClassSSRF          InjClass = "ssrf"
	ClassCmdi          InjClass = "cmdi"
	ClassLFI           InjClass = "lfi"
	ClassRFI           InjClass = "rfi"
	ClassPathTraversal InjClass = "path_traversal"
	ClassOpenRedirect  InjClass = "open_redirect"
	ClassSSTI          InjClass = "ssti"
)

// ParamLocation mirrors app.models.InjectionPoint.location.
type ParamLocation string

const (
	LocQuery    ParamLocation = "query"
	LocBodyForm ParamLocation = "body_form"
	LocBodyJSON ParamLocation = "body_json"
	LocPath     ParamLocation = "path"
	LocHeader   ParamLocation = "header"
	LocCookie   ParamLocation = "cookie"
)

// VerificationTier mirrors the spec's Potential / Likely / Verified ladder.
type VerificationTier string

const (
	TierNone      VerificationTier = "none"
	TierPotential VerificationTier = "potential"
	TierLikely    VerificationTier = "likely"
	TierVerified  VerificationTier = "verified"
)

var tierRank = map[VerificationTier]int{TierNone: 0, TierPotential: 1, TierLikely: 2, TierVerified: 3}

func maxTier(a, b VerificationTier) VerificationTier {
	if tierRank[b] > tierRank[a] {
		return b
	}
	return a
}

// InjParam is one classified, testable input point.
type InjParam struct {
	Method     string
	BaseURL    string // scheme://host/path, no query
	FullURL    string // the discovered sample URL (with query, if any)
	Name       string
	Location   ParamLocation
	Value      string
	ParamType  string // numeric | string | json | uuid | bool | unknown
	Technology []string
	Candidates []InjClass
}

// InjResult is one class's test outcome for a parameter.
type InjResult struct {
	Param           InjParam
	Class           InjClass
	Tier            VerificationTier
	Confidence      int
	EvidenceQuality int
	DetectionMethod string
	DBMS            string
	Context         string // html | attribute | javascript | url | css | json | dom_sink
	Evidence        string
	Extracted       []string
	CurlCommand     string
	Request         string
	ResponseExcerpt string
}

// injBaseline is the reference response a parameter's tests are compared
// against.
type injBaseline struct {
	status  int
	length  int
	body    string
	headers map[string][]string
	elapsed time.Duration
}

// ── parameter classification ────────────────────────────────────────────

var (
	reNumeric = regexp.MustCompile(`^-?\d+$`)
	reUUIDp   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reBool    = regexp.MustCompile(`(?i)^(true|false|0|1|yes|no)$`)
)

func classifyType(v string) string {
	switch {
	case v == "":
		return "unknown"
	case reUUIDp.MatchString(v):
		return "uuid"
	case reNumeric.MatchString(v):
		return "numeric"
	case reBool.MatchString(v):
		return "bool"
	default:
		return "string"
	}
}

// name-based candidate hints. SQLi, XSS and HTML-injection are considered for
// every string/numeric parameter (the two most universal, lowest-risk-to-test
// classes); the rest are only tried when the parameter name suggests the
// relevant sink, keeping the test volume proportionate to what's plausible.
var (
	reFileParam  = regexp.MustCompile(`(?i)^(file|filename|path|page|template|tpl|view|include|doc|document|download|resource|load)$`)
	reURLParam   = regexp.MustCompile(`(?i)(url|uri|link|href|src|callback|webhook|redirect|return|returnto|next|continue|image|imgurl|target|dest|destination|out|feed|proxy|fetch|host)`)
	reCmdParam   = regexp.MustCompile(`(?i)^(cmd|command|exec|run|ping|host|ip|addr|query_cmd|shell)$`)
	reTplParam   = regexp.MustCompile(`(?i)(template|tpl|view|render|layout)`)
	reRedirParam = regexp.MustCompile(`(?i)(redirect|return|returnto|next|continue|url|goto)`)
)

// classify assigns candidate vulnerability classes to a parameter based on its
// name and observed type. It is intentionally conservative: naming heuristics
// gate the higher-risk / narrower classes, but SQLi/XSS/HTML-injection are
// always considered since nearly any reflected or query-backed parameter can
// carry them.
func classify(name, value string) []InjClass {
	t := classifyType(value)
	classes := []InjClass{ClassSQLi}
	if t != "numeric" || true { // still worth trying numeric contexts for XSS/HTMLi reflection
		classes = append(classes, ClassXSS, ClassHTMLInjection)
	}
	switch {
	case reFileParam.MatchString(name):
		classes = append(classes, ClassLFI, ClassPathTraversal, ClassRFI)
	case reURLParam.MatchString(name):
		classes = append(classes, ClassSSRF, ClassRFI)
		if reRedirParam.MatchString(name) {
			classes = append(classes, ClassOpenRedirect)
		}
	case reCmdParam.MatchString(name):
		classes = append(classes, ClassCmdi)
	case reTplParam.MatchString(name):
		classes = append(classes, ClassSSTI)
	}
	// CRLF is plausible for anything that might land in a header/redirect —
	// cheap enough (one request) to just always include it.
	classes = append(classes, ClassCRLF)
	return uniqClasses(classes)
}

func uniqClasses(in []InjClass) []InjClass {
	seen := map[InjClass]bool{}
	var out []InjClass
	for _, c := range in {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// extractParams pulls query-string parameters out of a sample URL. POST
// form/JSON bodies aren't discovered by the current crawl phase, so those
// locations are supported by the detectors but not yet auto-populated here —
// see PERFORMANCE.md / known limitations.
func extractParams(rawurl, method string) []InjParam {
	u, err := url.Parse(rawurl)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	base := *u
	base.RawQuery = ""
	baseURL := base.String()

	var out []InjParam
	for k, vs := range u.Query() {
		v := ""
		if len(vs) > 0 {
			v = vs[0]
		}
		out = append(out, InjParam{
			Method: method, BaseURL: baseURL, FullURL: rawurl,
			Name: k, Location: LocQuery, Value: v,
			ParamType:  classifyType(v),
			Candidates: classify(k, v),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// buildURL returns baseURL with the query string rebuilt from `params`, with
// `name` overridden to `value` (URL-encoded).
func buildURL(baseURL string, params []InjParam, name, value string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := url.Values{}
	for _, p := range params {
		if p.Name == name {
			q.Set(p.Name, value)
		} else {
			q.Set(p.Name, p.Value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func curlFor(method, rawurl string) string {
	return fmt.Sprintf("curl -X '%s' '%s'", method, rawurl)
}

func toBaseline(resp *httpengine.Response) injBaseline {
	return injBaseline{
		status: resp.StatusCode, length: len(resp.Body), body: string(resp.Body),
		headers: resp.Header, elapsed: resp.Elapsed,
	}
}

// similarity is a cheap 0..1 structural comparison (length ratio + shared
// line count) — enough to tell "same page" from "meaningfully different page"
// without a heavyweight diff algorithm.
func bodySimilarity(a, b string) float64 {
	if a == "" && b == "" {
		return 1
	}
	la, lb := len(a), len(b)
	lenScore := 1.0
	if la != lb {
		big, small := la, lb
		if small > big {
			big, small = small, big
		}
		if big > 0 {
			lenScore = float64(small) / float64(big)
		}
	}
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")
	setB := map[string]bool{}
	for _, l := range linesB {
		setB[l] = true
	}
	shared := 0
	for _, l := range linesA {
		if setB[l] {
			shared++
		}
	}
	denom := len(linesA)
	if len(linesB) > denom {
		denom = len(linesB)
	}
	lineScore := 1.0
	if denom > 0 {
		lineScore = float64(shared) / float64(denom)
	}
	return (lenScore + lineScore) / 2
}

func trimN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func scopedURL(eng *scope.Engine, rawurl string) bool {
	h := hostOf(rawurl)
	if h == "" {
		return false
	}
	return eng.Evaluate(scope.Target{Host: h}).Allowed
}
