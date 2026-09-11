package recon

import (
	"context"
	"strings"

	"github.com/argus-platform/orchestrator/internal/httpengine"
)

// detectCRLF injects an encoded CRLF sequence carrying a uniquely-named
// header/cookie and checks whether it comes back as an actual response
// header — an unambiguous, zero-false-positive signal (no cache poisoning or
// persistent manipulation is attempted).
func detectCRLF(ctx context.Context, he *httpengine.Engine, p InjParam, params []InjParam) *InjResult {
	marker := "X-Argus-Crlf-" + randToken(3)
	cookieMarker := "argus_crlf_" + randToken(3)
	payload := p.Value + "%0d%0a" + marker + ": injected%0d%0aSet-Cookie: " + cookieMarker + "=1"
	u := buildURL(p.BaseURL, params, p.Name, payload)
	resp, err := he.Get(ctx, u)
	if err != nil {
		return nil
	}
	headerHit := resp.Header.Get(marker) != ""
	cookieHit := false
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(c, cookieMarker) {
			cookieHit = true
			break
		}
	}
	if !headerHit && !cookieHit {
		return nil
	}
	ev := "the injected sequence was reflected as a distinct response header"
	if cookieHit {
		ev = "the injected sequence set an attacker-controlled cookie via response-header injection"
	}
	return &InjResult{
		Param: p, Class: ClassCRLF, Tier: TierVerified, Confidence: 90, EvidenceQuality: 85,
		DetectionMethod: "header_injection",
		Evidence:        ev,
		CurlCommand:     curlFor(p.Method, u),
		Request:         "GET " + u,
	}
}
