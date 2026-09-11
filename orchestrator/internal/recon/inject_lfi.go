package recon

import (
	"context"
	"regexp"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
)

// knownFileSignatures are well-known, non-secret markers that only appear at
// the start of a handful of OS files. A match proves file disclosure; only a
// short, already-public-format snippet is ever stored as evidence (never the
// full file).
var knownFileSignatures = []struct {
	payload, sig, os string
}{
	{"/etc/passwd", `root:.*?:0:0:`, "unix"},
	{"/etc/hostname", `^[a-zA-Z0-9._-]{1,64}$`, "unix"},
	{"\\windows\\win.ini", `(?i)\[extensions\]|\[fonts\]`, "windows"},
	{"\\windows\\system.ini", `(?i)\[drivers\]|\[386Enh\]`, "windows"},
}

var traversalDepths = []int{3, 4, 5, 6, 8, 10}

// detectLFI proves path traversal two ways: (1) safely, by traversing back to
// the endpoint's *own* path and confirming the response matches the known
// baseline — no sensitive file is ever touched — and (2), as a secondary,
// lower-weight signal, a classic well-known-file probe whose evidence is
// stored as a short redacted snippet rather than full file content.
func detectLFI(ctx context.Context, he *httpengine.Engine, p InjParam, params []InjParam, base injBaseline) *InjResult {
	// ── safe self-referential traversal proof ───────────────────────────
	selfPath := pathOf(p.BaseURL)
	trimmedSelf := strings.TrimPrefix(selfPath, "/")
	if trimmedSelf != "" {
		for _, depth := range traversalDepths {
			trav := strings.Repeat("../", depth) + trimmedSelf
			u := buildURL(p.BaseURL, params, p.Name, trav)
			resp, err := he.Get(ctx, u)
			if err != nil {
				continue
			}
			if resp.StatusCode == base.status && bodySimilarity(base.body, string(resp.Body)) > 0.9 && len(resp.Body) > 0 {
				return &InjResult{
					Param: p, Class: ClassPathTraversal, Tier: TierVerified, Confidence: 87, EvidenceQuality: 82,
					DetectionMethod: "self_reference_traversal",
					Evidence: "requesting the endpoint's own path through " + itoa(depth) +
						" levels of \"../\" returned the same content — proves traversal without reading a sensitive file",
					CurlCommand: curlFor(p.Method, u),
					Request:     "GET " + u,
				}
			}
		}
	}

	// ── classic known-file signature (secondary, redacted evidence) ─────
	for _, depth := range []int{3, 6} {
		for _, kf := range knownFileSignatures {
			trav := strings.Repeat("../", depth) + strings.TrimPrefix(kf.payload, "/") + "\x00"
			travNoNull := strings.Repeat("../", depth) + strings.TrimPrefix(kf.payload, "/")
			for _, candidate := range []string{travNoNull, trav} {
				u := buildURL(p.BaseURL, params, p.Name, candidate)
				resp, err := he.Get(ctx, u)
				if err != nil {
					continue
				}
				re := regexp.MustCompile(kf.sig)
				if body := string(resp.Body); resp.StatusCode == 200 && re.MatchString(body) && !re.MatchString(base.body) {
					snippet := trimN(re.FindString(body), 60)
					return &InjResult{
						Param: p, Class: ClassLFI, Tier: TierLikely, Confidence: 72, EvidenceQuality: 60,
						DetectionMethod: "known_file_signature",
						Evidence:        "a " + kf.os + " system file signature was matched via " + itoa(depth) + "-level traversal (evidence redacted to a short match snippet)",
						Extracted:       []string{snippet},
						CurlCommand:     curlFor(p.Method, u),
						Request:         "GET " + u,
					}
				}
			}
		}
	}
	return nil
}

// detectRFI checks whether the application fetches a remote resource the
// scanner controls — see inject_ssrf.go for the shared OAST client.
func detectRFI(ctx context.Context, he *httpengine.Engine, oast *oastClient, p InjParam, params []InjParam) *InjResult {
	if oast == nil {
		return nil
	}
	token, callbackURL := oast.newToken()
	u := buildURL(p.BaseURL, params, p.Name, callbackURL)
	if _, err := he.Get(ctx, u); err != nil {
		return nil
	}
	if hit, detail := oast.wait(ctx, token, oastWaitTime); hit {
		return &InjResult{
			Param: p, Class: ClassRFI, Tier: TierVerified, Confidence: 93, EvidenceQuality: 90,
			DetectionMethod: "oast_callback",
			Evidence:        "the application fetched the scanner-controlled remote URL: " + detail,
			CurlCommand:     curlFor(p.Method, u),
			Request:         "GET " + u,
		}
	}
	return nil
}
