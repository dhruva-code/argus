package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const oastWaitTime = 8 * time.Second

var reHexProject = regexp.MustCompile(`^[0-9a-f]{32}$`)

// oastClient talks to the gateway's out-of-band collector (app/routers/oast.py).
// It is nil (disabled) unless a base URL is configured — SSRF/RFI verification
// is skipped entirely rather than sending a callback URL nothing will ever
// see, which would be worse than not testing at all.
type oastClient struct {
	collectorBase string // public(-ish) URL the TARGET can reach, e.g. https://argus.example.com/api/oast
	statusBase    string // gateway URL the ORCHESTRATOR can reach, e.g. http://gateway:8000
	internalToken string
	projectHex    string // project UUID, hex, no dashes
	http          *http.Client
}

func newOASTClient(collectorBase, statusBase, internalToken, projectID string) *oastClient {
	if collectorBase == "" {
		return nil
	}
	hex := strings.ReplaceAll(projectID, "-", "")
	if !reHexProject.MatchString(hex) {
		return nil
	}
	return &oastClient{
		collectorBase: strings.TrimRight(collectorBase, "/"),
		statusBase:    strings.TrimRight(statusBase, "/"),
		internalToken: internalToken,
		projectHex:    hex,
		http:          &http.Client{Timeout: 6 * time.Second},
	}
}

func (o *oastClient) newToken() (token, callbackURL string) {
	token = o.projectHex + randToken(8)
	return token, o.collectorBase + "/" + token
}

func (o *oastClient) wait(ctx context.Context, token string, max time.Duration) (bool, string) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if hit, detail := o.poll(ctx, token); hit {
			return true, detail
		}
		select {
		case <-ctx.Done():
			return false, ""
		case <-time.After(1200 * time.Millisecond):
		}
	}
	return false, ""
}

func (o *oastClient) poll(ctx context.Context, token string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", o.statusBase+"/api/internal/oast/status/"+token, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("X-Internal-Token", o.internalToken)
	resp, err := o.http.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	var out struct {
		Hit        bool   `json:"hit"`
		RemoteAddr string `json:"remote_addr"`
		Summary    string `json:"summary"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return false, ""
	}
	if out.Hit {
		return true, fmt.Sprintf("callback received from %s", out.RemoteAddr)
	}
	return false, ""
}

// detectSSRF sends the scanner's own OAST collector URL as the parameter
// value and waits for a callback. It never targets internal ranges or cloud
// metadata itself — the payload always points at our own external collector,
// so the platform is never the one directing traffic at private
// infrastructure; if the *target* resolves the callback host internally
// first that is the target's own DNS/network behaviour, not something this
// scanner requested.
func detectSSRF(ctx context.Context, oast *oastClient, doer func(ctx context.Context, url string) error, p InjParam, params []InjParam) *InjResult {
	if oast == nil {
		return nil
	}
	token, callbackURL := oast.newToken()
	u := buildURL(p.BaseURL, params, p.Name, callbackURL)
	if err := doer(ctx, u); err != nil {
		return nil
	}
	if hit, detail := oast.wait(ctx, token, oastWaitTime); hit {
		return &InjResult{
			Param: p, Class: ClassSSRF, Tier: TierVerified, Confidence: 95, EvidenceQuality: 92,
			DetectionMethod: "oast_callback",
			Evidence:        "the application made an outbound request to a scanner-controlled URL: " + detail,
			CurlCommand:     curlFor(p.Method, u),
			Request:         "GET " + u,
		}
	}
	return nil
}

// detectOpenRedirect sends a scanner-owned (never third-party) redirect
// target and checks whether the app issues a redirect to it.
func detectOpenRedirect(ctx context.Context, doer func(ctx context.Context, url string) (int, string, error), p InjParam, params []InjParam) *InjResult {
	marker := "argus-redirect-" + randToken(4) + ".invalid"
	target := "https://" + marker + "/"
	u := buildURL(p.BaseURL, params, p.Name, target)
	status, location, err := doer(ctx, u)
	if err != nil {
		return nil
	}
	if status >= 300 && status < 400 && strings.Contains(location, marker) {
		return &InjResult{
			Param: p, Class: ClassOpenRedirect, Tier: TierVerified, Confidence: 90, EvidenceQuality: 85,
			DetectionMethod: "redirect_location",
			Evidence:        "the application issued a " + itoa(status) + " redirect to the attacker-supplied host",
			CurlCommand:     curlFor(p.Method, u),
			Request:         "GET " + u,
		}
	}
	return nil
}
