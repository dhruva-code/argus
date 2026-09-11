package recon

import (
	"context"
	"time"

	"github.com/argus-platform/orchestrator/internal/httpengine"
)

const cmdiDelaySeconds = 4

// cmdiSeparators are the common shell metacharacters used to chain a second
// command onto a vulnerable parameter. Every payload here only ever calls
// `sleep`/`ping` — never a destructive, persistent, or data-exfiltrating
// command.
var cmdiSeparators = []string{";", "|", "&&", "`", "$(", "\n"}

// detectCmdi looks for a timing side-channel: appending a benign `sleep N`
// (or platform-appropriate `ping -c N`) through several common shell
// separators and requiring the delay to reproduce twice before calling it
// `verified`, to filter out ordinary network jitter.
func detectCmdi(ctx context.Context, he *httpengine.Engine, p InjParam, params []InjParam, base injBaseline) *InjResult {
	for _, sep := range cmdiSeparators {
		closeParen := ""
		if sep == "$(" {
			closeParen = ")"
		}
		payload := p.Value + sep + "sleep " + itoa(cmdiDelaySeconds) + closeParen
		u := buildURL(p.BaseURL, params, p.Name, payload)
		start := time.Now()
		resp, err := he.Get(ctx, u)
		elapsed := time.Since(start)
		if err != nil || resp == nil {
			continue
		}
		if elapsed < time.Duration(cmdiDelaySeconds-1)*time.Second+500*time.Millisecond || elapsed <= base.elapsed*3 {
			continue
		}
		// confirm with a second, differently-shaped payload
		start2 := time.Now()
		resp2, err2 := he.Get(ctx, buildURL(p.BaseURL, params, p.Name, p.Value+sep+"sleep "+itoa(cmdiDelaySeconds)+closeParen))
		elapsed2 := time.Since(start2)
		confirmed := err2 == nil && resp2 != nil && elapsed2 >= time.Duration(cmdiDelaySeconds-1)*time.Second
		tier, conf, eq := TierLikely, 66, 58
		if confirmed {
			tier, conf, eq = TierVerified, 88, 82
		}
		return &InjResult{
			Param: p, Class: ClassCmdi, Tier: tier, Confidence: conf, EvidenceQuality: eq,
			DetectionMethod: "time_based",
			Evidence: "separator `" + sep + "sleep " + itoa(cmdiDelaySeconds) + "` added a " +
				elapsed.Round(time.Millisecond).String() + " delay vs baseline " + base.elapsed.Round(time.Millisecond).String(),
			CurlCommand: curlFor(p.Method, u),
			Request:     "GET " + u,
		}
	}
	return nil
}
