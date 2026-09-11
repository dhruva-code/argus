package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/scope"
)

// PhaseDirDiscovery is the Phase 9 key.
const PhaseDirDiscovery = "directory_discovery"

// sensitivity classification rules, most specific first.
var sensitivityRules = []struct {
	re     *regexp.Regexp
	sev    string
	reason string
}{
	{regexp.MustCompile(`(?i)/\.git(/|/config|/HEAD|$)`), "critical", "Exposed .git directory — full source history recoverable"},
	{regexp.MustCompile(`(?i)/\.env(\.|$)`), "critical", "Environment file — likely credentials / configuration exposure"},
	{regexp.MustCompile(`(?i)/\.(svn|hg|bzr)(/|$)`), "critical", "Exposed VCS metadata"},
	{regexp.MustCompile(`(?i)\.(sql|dump|bak|backup|old|swp|tar\.gz|tgz|zip|rar|7z)$`), "high", "Backup / archive file"},
	{regexp.MustCompile(`(?i)/(wp-config|config|configuration|settings|secrets|credentials)\.(php|inc|json|ya?ml|xml|ini)$`), "high", "Configuration file"},
	{regexp.MustCompile(`(?i)/\.(aws|ssh|docker|kube)(/|$)`), "high", "Credential / cloud config directory"},
	{regexp.MustCompile(`(?i)/(id_rsa|id_dsa|id_ecdsa|\.htpasswd|\.netrc)$`), "critical", "Private key / credential file"},
	{regexp.MustCompile(`(?i)/(phpinfo|info)\.php$`), "medium", "PHP info disclosure"},
	{regexp.MustCompile(`(?i)/server-status|/server-info`), "medium", "Apache status page"},
	{regexp.MustCompile(`(?i)/actuator(/|$)|/actuator/env|/actuator/heapdump`), "high", "Spring Boot Actuator — often unauthenticated"},
	{regexp.MustCompile(`(?i)/(debug|trace|_debug)(/|$)`), "medium", "Debug endpoint"},
	{regexp.MustCompile(`(?i)/(admin|administrator|manage|management|console|dashboard)(/|$)`), "medium", "Admin panel"},
	{regexp.MustCompile(`(?i)/\.DS_Store$`), "low", "macOS metadata — leaks directory listing"},
	{regexp.MustCompile(`(?i)/(swagger|openapi|api-docs|graphiql)`), "low", "API documentation"},
	{regexp.MustCompile(`(?i)/(\.well-known/security\.txt)$`), "none", "security.txt (informational)"},
}

func classifySensitivity(path string) (string, string) {
	for _, rule := range sensitivityRules {
		if rule.re.MatchString(path) {
			return rule.sev, rule.reason
		}
	}
	return "none", ""
}

// ── ffuf ──────────────────────────────────────────────────────────────────

type ffufResult struct {
	Results []struct {
		Input struct {
			FUZZ string `json:"FUZZ"`
		} `json:"input"`
		URL         string `json:"url"`
		Status      int    `json:"status"`
		Length      int    `json:"length"`
		ContentType string `json:"content-type"`
	} `json:"results"`
}

func ffufHost(ctx context.Context, r plugin.Runner, dir, host, baseURL, wordlist string, rps, maxBytes int) (*ffufResult, error) {
	bin, err := r.Look("ffuf")
	if err != nil {
		return nil, err
	}
	outPath := filepath.Join(dir, "ffuf-"+sanitize(host)+".json")
	// Content discovery on a single host tolerates more concurrency than a
	// broad crawl; keep it bounded but not glacial.
	rate := rps * 4
	if rate < 30 {
		rate = 30
	}
	argv := []string{
		bin, "-u", strings.TrimRight(baseURL, "/") + "/FUZZ", "-w", wordlist,
		"-mc", "200,201,204,301,302,307,401,403,405,500",
		"-o", outPath, "-of", "json", "-s", "-noninteractive",
		"-t", "40", "-timeout", "7", "-rate", itoa(rate),
		"-maxtime-job", "180",
	}
	if maxBytes > 0 {
		argv = append(argv, "-fs", itoa(maxBytes)) // filter responses bigger than the cap
	}
	if _, _, err := r.Exec(ctx, argv); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		return nil, err
	}
	var res ffufResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// runDirDiscovery fuzzes each alive in-scope host with the configured wordlist
// and classifies every hit's sensitivity. It never downloads large bodies
// (ffuf -fs cap) and emits results as endpoints.
func runDirDiscovery(
	ctx context.Context, r plugin.Runner, eng *scope.Engine, dir string,
	aliveHosts []string, aliveBase map[string]string, wordlist string, opts Options, cb Callbacks,
) int {
	if wordlist == "" {
		cb.log("WARNING", "directory discovery skipped — no wordlist configured (ARGUS_WORDLISTS_DIR)")
		return 0
	}
	if _, err := os.Stat(wordlist); err != nil {
		cb.log("WARNING", "directory discovery skipped — wordlist not found: "+wordlist)
		return 0
	}
	hosts := aliveHosts
	if len(hosts) > 20 {
		hosts = hosts[:20]
		cb.log("WARNING", fmt.Sprintf("fuzzing the first 20 of %d alive hosts", len(aliveHosts)))
	}
	total := 0
	for _, h := range hosts {
		if cb.cancelled() {
			break
		}
		if !eng.Evaluate(scope.Target{Host: h}).Allowed {
			continue
		}
		res, err := ffufHost(ctx, r, dir, h, baseURLFor(h, aliveBase), wordlist, opts.RequestsPerSecond, opts.MaxResponseBytes())
		if err != nil {
			cb.log("WARNING", "ffuf "+h+": "+err.Error())
			continue
		}
		for _, hit := range res.Results {
			path := "/" + strings.TrimPrefix(hit.Input.FUZZ, "/")
			sev, reason := classifySensitivity(path)
			ep, ok := makeEndpoint(hit.URL, "GET", eng, "ffuf")
			if !ok || !ep.InScope {
				continue
			}
			ep.StatusCode = hit.Status
			ep.ContentType = hit.ContentType
			ep.ContentLength = hit.Length
			ep.Sensitivity = sev
			ep.SensitivityReason = reason
			ep.Tags = appendUniq(ep.Tags, "content-discovery")
			if sev != "none" {
				ep.Tags = appendUniq(ep.Tags, "sensitive")
			}
			cb.emitEndpoint(ep)
			total++
			if sev == "critical" || sev == "high" {
				cb.log("WARNING", fmt.Sprintf("sensitive path %s [%d] — %s", hit.URL, hit.Status, reason))
			}
		}
	}
	cb.log("INFO", fmt.Sprintf("directory discovery — %d path(s) across %d host(s)", total, len(hosts)))
	return total
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "_", ":", "_", "*", "_", ".", "-").Replace(s)
}

// MaxResponseBytes exposes the per-request cap for tools that support it.
func (o Options) MaxResponseBytes() int {
	if o.maxResponseBytes > 0 {
		return o.maxResponseBytes
	}
	return 512 << 10
}

// SetMaxResponseBytes sets the per-request body cap (from the scan profile).
func (o *Options) SetMaxResponseBytes(n int) {
	if n > 0 {
		o.maxResponseBytes = n
	}
}
