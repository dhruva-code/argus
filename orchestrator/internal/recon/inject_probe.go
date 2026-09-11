package recon

import (
	"context"
	"regexp"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
)

// captureBaseline fetches the endpoint with its original parameter values —
// the reference every detector diffs against.
func captureBaseline(ctx context.Context, he *httpengine.Engine, rawurl string) (injBaseline, error) {
	resp, err := he.Get(ctx, rawurl)
	if err != nil {
		return injBaseline{}, err
	}
	return toBaseline(resp), nil
}

// reflectionContext classifies where (if at all) a marker string shows up in
// an HTML response, and whether it was encoded on the way in.
type reflection struct {
	found      bool
	encoded    bool // entity-encoded (&lt; etc.) — safe
	context    string
	occurrence string // a short excerpt around the reflection, for evidence
}

var (
	reScriptBlock = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	reAttrCtx     = regexp.MustCompile(`(?i)=\s*["'][^"']*$`)
	reJSONCtx     = regexp.MustCompile(`(?i)^\s*[{\[]`)
)

// probeReflection injects a unique marker into exactly one parameter and
// classifies how (and where) it comes back. This single request underlies
// both the XSS and HTML-injection detectors, and short-circuits both when the
// marker never reflects.
func probeReflection(ctx context.Context, he *httpengine.Engine, p InjParam, params []InjParam) (reflection, injBaseline, error) {
	marker := "argusRX" + randToken(4)
	// a string with both an HTML metacharacter and a quote, so we can tell
	// encoded from raw reflection in one shot
	payload := marker + `"'<>`
	u := buildURL(p.BaseURL, params, p.Name, payload)
	resp, err := he.Get(ctx, u)
	if err != nil {
		return reflection{}, injBaseline{}, err
	}
	b := toBaseline(resp)
	body := b.body

	if strings.Contains(body, payload) {
		return reflection{found: true, encoded: false, context: reflectionCtx(body, payload), occurrence: excerptAround(body, payload)}, b, nil
	}
	encodedForm := strings.NewReplacer(`"`, "&quot;", `'`, "&#39;", `<`, "&lt;", `>`, "&gt;").Replace(payload)
	if strings.Contains(body, encodedForm) || strings.Contains(body, marker) {
		return reflection{found: true, encoded: !strings.Contains(body, payload), context: "html", occurrence: excerptAround(body, marker)}, b, nil
	}
	return reflection{found: false}, b, nil
}

func reflectionCtx(body, marker string) string {
	i := strings.Index(body, marker)
	if i < 0 {
		return "html"
	}
	before := body[:i]
	// inside a <script> block?
	if m := reScriptBlock.FindAllStringIndex(body, -1); m != nil {
		for _, span := range m {
			if i >= span[0] && i < span[1] {
				return "javascript"
			}
		}
	}
	// last 80 chars before the marker end in an open attribute quote?
	tail := before
	if len(tail) > 80 {
		tail = tail[len(tail)-80:]
	}
	if reAttrCtx.MatchString(tail) {
		return "attribute"
	}
	if reJSONCtx.MatchString(strings.TrimSpace(body)) {
		return "json"
	}
	return "html"
}

func excerptAround(body, marker string) string {
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + len(marker) + 40
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}
