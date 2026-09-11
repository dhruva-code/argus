package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// fetchAuthProfile retrieves a decrypted Authentication Profile (§17) from the
// gateway just-in-time, over the internal-token-guarded endpoint. The value
// is held only in memory for the lifetime of this call chain — it is never
// written into job params, Redis, the database, or any log line. Callers
// must not log the returned value.
func (e *Engine) fetchAuthProfile(ctx context.Context, profileID string) (headerName, headerValue string, err error) {
	if e.cfg.InternalToken == "" {
		return "", "", fmt.Errorf("orchestrator has no internal token configured")
	}
	url := fmt.Sprintf("%s/api/internal/auth-profiles/%s", trimRightSlash(e.cfg.GatewayURL), profileID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-Internal-Token", e.cfg.InternalToken)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("gateway returned %d fetching auth profile", resp.StatusCode)
	}

	var out struct {
		HeaderName  string `json:"header_name"`
		HeaderValue string `json:"header_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("decoding auth profile response: %w", err)
	}
	if out.HeaderName == "" || out.HeaderValue == "" {
		return "", "", fmt.Errorf("auth profile response missing header name/value")
	}
	// Deliberately no log line here — see doc comment above.
	return out.HeaderName, out.HeaderValue, nil
}

func trimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
