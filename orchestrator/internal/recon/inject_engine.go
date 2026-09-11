package recon

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
	"github.com/argus-platform/orchestrator/internal/scope"
	"github.com/argus-platform/orchestrator/internal/ssrf"
)

// InjPointRecord is emitted once per classified parameter — the row behind
// the Injection Point Explorer (§12), regardless of test outcome.
type InjPointRecord struct {
	Method           string   `json:"method"`
	URL              string   `json:"url"`
	Host             string   `json:"host"`
	ParamName        string   `json:"param_name"`
	Location         string   `json:"location"`
	ParamType        string   `json:"param_type"`
	Context          string   `json:"context,omitempty"`
	Technology       []string `json:"technology,omitempty"`
	AuthState        string   `json:"auth_state"`
	CandidateClasses []string `json:"candidate_classes"`
	TestedClasses    []string `json:"tested_classes"`
	BestResult       string   `json:"best_result"`
	Confidence       int      `json:"confidence"`
}

// injectionOptions configures the engine; all fields have safe zero-values
// (fully disabled) so a caller that doesn't set them up gets no active
// injection traffic at all.
type injectionOptions struct {
	MaxParams        int    // cap on distinct parameters tested (cost control)
	EnableSSRF       bool   // §7 — requires the advanced-testing policy, not just injection_ack
	OASTCollectorURL string // public collector base the target can reach; "" disables SSRF/RFI
	OASTStatusURL    string // gateway URL the orchestrator itself can reach
	OASTInternalTok  string
	ProjectID        string
	BrowserBinary    string // resolved once by the caller; "" disables XSS browser verification
	AuthHeaderName   string // optional Authentication Profile (§17), attached to every test request
	AuthHeaderValue  string
	TestHeaders      bool // §1 "headers where explicitly enabled"
	TestCookies      bool // §1 "cookies where explicitly enabled"
}

// runInjectionTesting is the Injection Testing Engine's phase entry point. It
// classifies every in-scope, parameterised URL discovered so far, runs the
// pipeline in §2 (baseline → low-impact detection → comparison → candidate →
// safe verification → evidence → confidence → finding) per class, and emits
// an InjPoint for every parameter plus a Finding for every likely/verified
// result.
func runInjectionTesting(
	ctx context.Context, eng *scope.Engine, guard *ssrf.Guard,
	paramURLs []string, opts Options, iopts injectionOptions, cb Callbacks,
) (points int, findings int) {
	he := httpengine.New(eng, guard, httpengine.Options{
		RequestsPerSecond: max1(opts.RequestsPerSecond/2, 3), // injection testing is slower/heavier per-request than crawling
		TimeoutSeconds:    15,
		MaxResponseBytes:  int64(opts.MaxResponseBytes()),
	})

	var oast *oastClient
	if iopts.EnableSSRF && iopts.OASTCollectorURL != "" {
		oast = newOASTClient(iopts.OASTCollectorURL, iopts.OASTStatusURL, iopts.OASTInternalTok, iopts.ProjectID)
		if oast == nil {
			cb.log("WARNING", "SSRF/RFI OAST verification requested but the collector is not configured — those classes are skipped")
		}
	}
	browserBin := iopts.BrowserBinary

	// collect + dedup candidate parameters across all discovered URLs
	seen := map[string]bool{}
	var all []InjParam
	for _, raw := range paramURLs {
		if !scopedURL(eng, raw) {
			continue
		}
		for _, p := range extractParams(raw, "GET") {
			key := p.Method + " " + p.BaseURL + "?" + p.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, p)
		}
	}
	cap := iopts.MaxParams
	if cap <= 0 {
		cap = 60
	}
	if len(all) > cap {
		cb.log("WARNING", fmt.Sprintf("injection testing — capping at %d of %d discovered parameters", cap, len(all)))
		all = all[:cap]
	}
	cb.log("WARNING", fmt.Sprintf("PHASE injection_testing — %d parameter(s) across %d class(es) each", len(all), 6))

	for _, p := range all {
		if cb.cancelled() {
			break
		}
		rec, results := testOneParam(ctx, he, guard, eng, oast, browserBin, p)
		points++
		cb.emitInjPoint(rec)

		for _, r := range results {
			if r == nil || tierRank[r.Tier] < tierRank[TierLikely] {
				continue // only likely/verified become Findings; potential stays explorer-only
			}
			f := injResultToFinding(r)
			cb.emitFinding(f)
			findings++
			cb.log("WARNING", fmt.Sprintf("%s injection finding (%s, %s): %s at %s",
				r.Class, r.Tier, r.DetectionMethod, r.Param.Name, r.Param.BaseURL))
		}
	}
	cb.log("INFO", fmt.Sprintf("injection testing — %d parameter(s) classified, %d finding(s)", points, findings))
	return points, findings
}

// testOneParam runs every candidate class for one parameter and returns the
// explorer record plus each class's result (nil entries are omitted classes
// or clean results).
func testOneParam(
	ctx context.Context, he *httpengine.Engine, guard *ssrf.Guard, eng *scope.Engine,
	oast *oastClient, browserBin string, p InjParam,
) (InjPointRecord, []*InjResult) {
	params := []InjParam{p} // buildURL only needs name/value pairs for this one endpoint's query
	base, err := captureBaseline(ctx, he, p.FullURL)
	rec := InjPointRecord{
		Method: p.Method, URL: p.BaseURL, Host: hostOf(p.BaseURL),
		ParamName: p.Name, Location: string(p.Location), ParamType: p.ParamType,
		AuthState: "unauthenticated", CandidateClasses: classSliceToStr(p.Candidates),
		BestResult: "untested",
	}
	if err != nil {
		return rec, nil
	}

	var results []*InjResult
	tested := map[InjClass]bool{}
	bestTier := TierNone
	bestConf := 0
	run := func(class InjClass, fn func() *InjResult) {
		if tested[class] {
			return
		}
		tested[class] = true
		r := fn()
		results = append(results, r)
		if r != nil {
			if tierRank[r.Tier] > tierRank[bestTier] {
				bestTier = r.Tier
			}
			if r.Confidence > bestConf {
				bestConf = r.Confidence
			}
			if r.Context != "" {
				rec.Context = r.Context
			}
		}
	}

	for _, class := range p.Candidates {
		switch class {
		case ClassSQLi:
			run(ClassSQLi, func() *InjResult { return detectSQLi(ctx, he, p, params, base) })
		case ClassXSS, ClassHTMLInjection:
			// one reflection probe feeds both — only run once
			run(ClassXSS, func() *InjResult { return detectXSSOrHTMLInjection(ctx, he, browserBin, p, params) })
		case ClassCRLF:
			run(ClassCRLF, func() *InjResult { return detectCRLF(ctx, he, p, params) })
		case ClassCmdi:
			run(ClassCmdi, func() *InjResult { return detectCmdi(ctx, he, p, params, base) })
		case ClassLFI, ClassPathTraversal:
			run(ClassLFI, func() *InjResult { return detectLFI(ctx, he, p, params, base) })
		case ClassRFI:
			run(ClassRFI, func() *InjResult { return detectRFI(ctx, he, oast, p, params) })
		case ClassSSRF:
			if oast != nil {
				run(ClassSSRF, func() *InjResult {
					return detectSSRF(ctx, oast, func(c context.Context, u string) error {
						_, err := he.Get(c, u)
						return err
					}, p, params)
				})
			}
		case ClassOpenRedirect:
			run(ClassOpenRedirect, func() *InjResult {
				return detectOpenRedirect(ctx, func(c context.Context, u string) (int, string, error) {
					resp, err := he.Do(c, http.MethodGet, u, "")
					if err != nil {
						return 0, "", err
					}
					return resp.StatusCode, resp.Header.Get("Location"), nil
				}, p, params)
			})
		}
	}

	rec.TestedClasses = classSliceToStr(classKeys(tested))
	rec.Confidence = bestConf
	rec.BestResult = string(bestTier)
	if rec.BestResult == "" {
		rec.BestResult = "none"
	}
	return rec, results
}

func classKeys(m map[InjClass]bool) []InjClass {
	out := make([]InjClass, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func classSliceToStr(cs []InjClass) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c)
	}
	return out
}

func injResultToFinding(r *InjResult) Finding {
	sev := "medium"
	switch r.Class {
	case ClassSQLi, ClassCmdi, ClassSSRF, ClassRFI:
		sev = "critical"
	case ClassXSS, ClassLFI, ClassPathTraversal:
		sev = "high"
	case ClassCRLF, ClassOpenRedirect:
		sev = "medium"
	case ClassHTMLInjection:
		sev = "low"
	}
	if r.Tier == TierLikely {
		// one notch down from the verified severity until confirmed
		sev = downgradeSeverity(sev)
	}
	host := hostOf(r.Param.BaseURL)
	np, _ := normalizePath(pathOf(r.Param.BaseURL))
	name := fmt.Sprintf("%s — %s parameter `%s`", injClassLabel(r.Class), strings.ToUpper(r.Tier2()), r.Param.Name)
	return Finding{
		Fingerprint:      findingFingerprint("injection-"+string(r.Class), host, np, r.Param.Name),
		TemplateID:       "injection-" + string(r.Class),
		Name:             name,
		Severity:         sev,
		Engine:           "injection-engine",
		Tags:             []string{"injection", string(r.Class), string(r.Tier)},
		Host:             host,
		MatchedAt:        r.Param.FullURL,
		NormalizedPath:   np,
		MatcherName:      r.DetectionMethod,
		Extracted:        r.Extracted,
		Request:          r.Request,
		ResponseExcerpt:  r.ResponseExcerpt,
		CurlCommand:      r.CurlCommand,
		Description:      r.Evidence,
		Level:            VulnLevelAggressive,
		OOBConfirmed:     r.DetectionMethod == "oast_callback" || r.DetectionMethod == "browser_execution",
		InScope:          true,
		Parameter:        r.Param.Name,
		ParamLocation:    string(r.Param.Location),
		InjectionClass:   string(r.Class),
		DetectionMethod:  r.DetectionMethod,
		VerificationTier: string(r.Tier),
		EvidenceQuality:  r.EvidenceQuality,
	}
}

func (r *InjResult) Tier2() string { return string(r.Tier) }

func injClassLabel(c InjClass) string {
	labels := map[InjClass]string{
		ClassSQLi: "SQL Injection", ClassXSS: "Cross-Site Scripting", ClassHTMLInjection: "HTML Injection",
		ClassCRLF: "CRLF Injection", ClassSSRF: "SSRF", ClassCmdi: "OS Command Injection",
		ClassLFI: "Local File Inclusion", ClassRFI: "Remote File Inclusion",
		ClassPathTraversal: "Path Traversal", ClassOpenRedirect: "Open Redirect", ClassSSTI: "Template Injection",
	}
	if l, ok := labels[c]; ok {
		return l
	}
	return string(c)
}

func downgradeSeverity(sev string) string {
	switch sev {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return sev
	}
}

func max1(n, floor int) int {
	if n < floor {
		return floor
	}
	return n
}
