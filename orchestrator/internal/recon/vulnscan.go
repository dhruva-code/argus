package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/scope"
)

// PhaseVulnScan is the Phase 12 key.
const PhaseVulnScan = "automated_vuln_scan"

// Vulnerability-scan levels — the spec's passive / safe-verify / manual-review
// model, plus an explicitly-acknowledged `aggressive` level that adds
// template-controlled active injection fuzzing (Nuclei DAST).
const (
	VulnLevelPassive    = "passive"       // exposure / misconfig / tech only
	VulnLevelSafeVerify = "safe_verify"   // + CVEs / default-logins, OOB verification
	VulnLevelManual     = "manual_review" // same coverage; findings land needs_review
	VulnLevelAggressive = "aggressive"    // + active injection fuzzing of in-scope params
)

// Finding is a vulnerability-scanner result emitted as a "finding" event. The
// gateway's verification engine deduplicates and scores it.
type Finding struct {
	Fingerprint     string   `json:"fingerprint"`
	TemplateID      string   `json:"template_id"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	Engine          string   `json:"engine"`
	TemplateVersion string   `json:"template_version,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Host            string   `json:"host"`
	MatchedAt       string   `json:"matched_at"`
	NormalizedPath  string   `json:"normalized_path"`
	MatcherName     string   `json:"matcher_name,omitempty"`
	Extracted       []string `json:"extracted,omitempty"`
	Request         string   `json:"request,omitempty"`
	ResponseExcerpt string   `json:"response_excerpt,omitempty"`
	CurlCommand     string   `json:"curl_command,omitempty"`
	Reference       []string `json:"reference,omitempty"`
	CVE             []string `json:"cve,omitempty"`
	CWE             []string `json:"cwe,omitempty"`
	CVSSScore       float64  `json:"cvss_score,omitempty"`
	Description     string   `json:"description,omitempty"`
	Remediation     string   `json:"remediation,omitempty"`
	OOBConfirmed    bool     `json:"oob_confirmed,omitempty"`
	Level           string   `json:"level"`
	InScope         bool     `json:"in_scope"`
	// Injection Testing Engine (§1-13) — empty/zero for non-injection findings.
	Parameter        string `json:"parameter,omitempty"`
	ParamLocation    string `json:"param_location,omitempty"`
	InjectionClass   string `json:"injection_class,omitempty"`
	DetectionMethod  string `json:"detection_method,omitempty"`
	VerificationTier string `json:"verification_tier,omitempty"`
	EvidenceQuality  int    `json:"evidence_quality,omitempty"`
}

// runVulnScan is Phase 12: a bounded, scope-checked Nuclei run against the alive
// in-scope hosts (and a capped sample of discovered endpoints). The dangerous
// template classes (dos / intrusive / fuzzing / bruteforce) are always
// excluded; `level` widens coverage and enables out-of-band verification. At the
// `aggressive` level (explicitly acknowledged) it also runs Nuclei DAST —
// template-controlled active injection fuzzing — against in-scope endpoint URLs
// that carry parameters.
func runVulnScan(
	ctx context.Context, r plugin.Runner, eng *scope.Engine,
	dir string, targets, paramURLs []string, level string, opts Options, cb Callbacks,
) int {
	// keep only in-scope targets
	var scoped []string
	for _, t := range targets {
		h := hostOf(t)
		if h == "" || !eng.Evaluate(scope.Target{Host: h}).Allowed {
			continue
		}
		scoped = append(scoped, t)
	}
	scoped = uniqSorted(scoped)
	if len(scoped) == 0 {
		cb.log("INFO", "vulnerability scan — no in-scope targets")
		return 0
	}
	cap := opts.MaxVulnTargets
	if cap <= 0 {
		cap = 15
	}
	if len(scoped) > cap {
		cb.log("WARNING", fmt.Sprintf("vulnerability scan — capping at %d of %d targets", cap, len(scoped)))
		scoped = scoped[:cap]
	}

	tv := nucleiTemplatesVersion(ctx, r)
	cb.log("INFO", fmt.Sprintf("PHASE automated_vuln_scan — %s level, %d target(s), templates %s",
		level, len(scoped), orNone(tv)))

	rows, warn, err := nucleiScan(ctx, r, dir, scoped, level, opts)
	if warn != "" {
		cb.log("WARNING", "nuclei: "+warn)
	}
	if err != nil {
		cb.log("WARNING", "nuclei: "+err.Error())
		return 0
	}

	seen := map[string]bool{}
	n := 0
	for _, row := range rows {
		f := row.toFinding(level, tv)
		if f.Fingerprint == "" || seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		f.InScope = eng.Evaluate(scope.Target{Host: f.Host}).Allowed
		cb.emitFinding(f)
		n++
		if f.Severity == "high" || f.Severity == "critical" {
			cb.log("WARNING", fmt.Sprintf("%s finding: %s at %s", f.Severity, f.TemplateID, f.MatchedAt))
		}
	}
	cb.log("INFO", fmt.Sprintf("vulnerability scan — %d distinct finding(s) from %d raw match(es)", n, len(rows)))

	// ── aggressive: template-controlled active injection fuzzing ──────────
	if level == VulnLevelAggressive && !cb.cancelled() {
		injURLs := scopedParamURLs(eng, paramURLs, opts)
		if len(injURLs) == 0 {
			cb.log("INFO", "injection fuzzing — no in-scope parameterised endpoints to test")
			return n
		}
		cb.log("WARNING", fmt.Sprintf("PHASE injection fuzzing (Nuclei DAST) — %d in-scope endpoint(s)", len(injURLs)))
		drows, dwarn, _ := nucleiDAST(ctx, r, dir, injURLs, opts)
		if dwarn != "" {
			cb.log("WARNING", "nuclei dast: "+dwarn)
		}
		dn := 0
		for _, row := range drows {
			f := row.toFinding(VulnLevelAggressive, tv)
			f.Engine = "nuclei-dast"
			f.Tags = appendUniq(f.Tags, "injection")
			if f.Fingerprint == "" || seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true
			f.InScope = eng.Evaluate(scope.Target{Host: f.Host}).Allowed
			cb.emitFinding(f)
			dn++
			n++
			cb.log("WARNING", fmt.Sprintf("%s injection finding: %s at %s", f.Severity, f.TemplateID, f.MatchedAt))
		}
		cb.log("INFO", fmt.Sprintf("injection fuzzing — %d finding(s)", dn))
	}
	return n
}

// scopedParamURLs keeps only in-scope endpoint URLs that carry a query string,
// deduplicated by host+path+sorted-param-names and capped.
func scopedParamURLs(eng *scope.Engine, urls []string, opts Options) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		if !strings.Contains(u, "?") {
			continue
		}
		h := hostOf(u)
		if h == "" || !eng.Evaluate(scope.Target{Host: h}).Allowed {
			continue
		}
		key := h + pathOf(strings.SplitN(u, "?", 2)[0])
		// keep at most a couple of URLs per path (different param values)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	sort.Strings(out)
	cap := opts.MaxVulnTargets * 3
	if cap < 30 {
		cap = 30
	}
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}

// nucleiDAST runs Nuclei's DAST (fuzzing) templates against the given URLs. It
// is deliberately slower and lower-concurrency than the passive scan because it
// sends many payloads per parameter; scope is enforced with `-fuzz-scope`.
func nucleiDAST(ctx context.Context, r plugin.Runner, dir string, urls []string, opts Options) ([]nucleiRow, string, error) {
	bin, err := r.Look("nuclei")
	if err != nil {
		return nil, "", err
	}
	lf, err := writeList(dir, "nuclei-dast-targets.txt", urls)
	if err != nil {
		return nil, "", err
	}
	outPath := filepath.Join(dir, "nuclei-dast-out.jsonl")

	// in-scope host regex so the fuzzer never wanders off the allow-list
	hostSet := map[string]bool{}
	for _, u := range urls {
		if h := hostOf(u); h != "" {
			hostSet[h] = true
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, regexp.QuoteMeta(h))
	}
	sort.Strings(hosts)
	scopeRe := `https?://(` + strings.Join(hosts, "|") + `)/`

	rl := opts.RequestsPerSecond
	if rl < 5 {
		rl = 5
	}
	if rl > 25 {
		rl = 25
	}
	argv := []string{
		bin, "-list", lf, "-dast", "-jsonl", "-o", outPath,
		"-disable-update-check", "-no-color", "-silent",
		"-timeout", "8", "-retries", "1", "-c", "10", "-payload-concurrency", "10",
		"-rate-limit", itoa(rl), "-max-time", "12m", "-stats", "-stats-interval", "30",
		"-fuzz-aggression", "low", "-fuzz-scope", scopeRe,
		"-exclude-tags", "dos",
		"-header", "User-Agent: " + userAgent,
	}
	stdout, code, _ := r.Exec(ctx, argv)
	raw, _ := os.ReadFile(outPath)
	var rows []nucleiRow
	for _, blob := range []string{string(raw), stdout} {
		for _, ln := range strings.Split(blob, "\n") {
			ln = strings.TrimSpace(ln)
			if !strings.HasPrefix(ln, "{") {
				continue
			}
			var row nucleiRow
			if json.Unmarshal([]byte(ln), &row) == nil && row.TemplateID != "" {
				rows = append(rows, row)
			}
		}
	}
	warn := ""
	if len(rows) == 0 {
		warn = fmt.Sprintf("no injection findings (exit %d)", code)
		if tail := lastLines(stripJSONLines(stdout), 3); tail != "" {
			warn += " — " + tail
		}
	}
	return rows, warn, nil
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// ── nuclei adapter ────────────────────────────────────────────────────────

type nucleiInfo struct {
	Name        string   `json:"name"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
	Reference   []string `json:"reference"`
	Severity    string   `json:"severity"`
	Remediation string   `json:"remediation"`
	Class       struct {
		CVEID    any      `json:"cve-id"`
		CWEID    []string `json:"cwe-id"`
		CVSS     string   `json:"cvss-metrics"`
		CVSSCore float64  `json:"cvss-score"`
	} `json:"classification"`
}

type nucleiRow struct {
	TemplateID  string     `json:"template-id"`
	Info        nucleiInfo `json:"info"`
	Type        string     `json:"type"`
	Host        string     `json:"host"`
	MatchedAt   string     `json:"matched-at"`
	MatcherName string     `json:"matcher-name"`
	ExtractedR  []string   `json:"extracted-results"`
	Request     string     `json:"request"`
	Response    string     `json:"response"`
	CurlCommand string     `json:"curl-command"`
	IP          string     `json:"ip"`
	Interaction *struct {
		Protocol string `json:"protocol"`
	} `json:"interaction"`
}

func (row nucleiRow) toFinding(level, tv string) Finding {
	matchedAt := row.MatchedAt
	if matchedAt == "" {
		matchedAt = row.Host
	}
	host := hostOf(matchedAt)
	if host == "" {
		host = row.Host
	}
	np := pathOf(matchedAt)
	np, _ = normalizePath(strings.SplitN(np, "?", 2)[0])

	var cves []string
	switch v := row.Info.Class.CVEID.(type) {
	case string:
		if v != "" {
			cves = []string{strings.ToUpper(v)}
		}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				cves = append(cves, strings.ToUpper(s))
			}
		}
	}

	sev := strings.ToLower(row.Info.Severity)
	if sev == "" {
		sev = "info"
	}

	f := Finding{
		Fingerprint:     findingFingerprint(row.TemplateID, host, np, row.MatcherName),
		TemplateID:      row.TemplateID,
		Name:            row.Info.Name,
		Severity:        sev,
		Engine:          "nuclei",
		TemplateVersion: tv,
		Tags:            row.Info.Tags,
		Host:            host,
		MatchedAt:       trim(matchedAt, 1000),
		NormalizedPath:  np,
		MatcherName:     row.MatcherName,
		Extracted:       row.ExtractedR,
		Request:         trim(row.Request, 4000),
		ResponseExcerpt: trim(row.Response, 4000),
		CurlCommand:     trim(row.CurlCommand, 2000),
		Reference:       row.Info.Reference,
		CVE:             cves,
		CWE:             row.Info.Class.CWEID,
		CVSSScore:       row.Info.Class.CVSSCore,
		Description:     trim(strings.TrimSpace(row.Info.Description), 1000),
		Remediation:     trim(strings.TrimSpace(row.Info.Remediation), 1000),
		OOBConfirmed:    row.Interaction != nil,
		Level:           level,
	}
	return f
}

func findingFingerprint(templateID, host, path, matcher string) string {
	h := sha256.Sum256([]byte(templateID + "|" + host + "|" + path + "|" + matcher))
	return hex.EncodeToString(h[:])
}

// template directories per level. `http/technologies/` and the full
// `http/cves/` tree are deliberately left out — the former is ~900 templates of
// pure fingerprint noise (the verification engine pins those low anyway) and the
// latter is ~4k templates that are only meaningful once tech is known; both blow
// the phase budget. Deep CVE coverage is a template-profile feature for M6.
var vulnTemplateDirs = map[string][]string{
	VulnLevelPassive: {
		"http/exposures/", "http/misconfiguration/", "http/takeovers/",
		"ssl/", "dns/",
	},
	VulnLevelSafeVerify: {
		"http/exposures/", "http/misconfiguration/", "http/takeovers/",
		"http/default-logins/", "http/vulnerabilities/", "ssl/", "dns/", "network/",
	},
}

// noisy nuclei template ids the verification engine would pin to low confidence
// anyway — excluded at the source to keep ingestion lean. Mirrors
// apis/gateway/app/services/findings.py:_LOW_SIGNAL_TEMPLATES.
var noisyTemplateIDs = []string{
	"http-missing-security-headers", "missing-sri", "options-method", "http-trace",
	"waf-detect", "tls-version", "deprecated-tls", "weak-cipher-suites",
	"ssl-issuer", "ssl-dns-names", "self-signed-ssl", "x-powered-by-header",
	"cookies-without-httponly", "cookies-without-secure", "robots-txt-endpoint",
	"caa-fingerprint", "dmarc-detect", "spf-record-detect", "txt-fingerprint",
	"nameserver-fingerprint", "mx-fingerprint", "aaaa-fingerprint", "a-fingerprint",
	"ns-fingerprint", "cname-fingerprint", "soa-detect",
}

// nucleiMaxRuntime is nuclei's own `-mt` self-termination budget — it flushes
// results cleanly, unlike a context kill. Kept under the phase budget.
const nucleiMaxRuntime = "18m"

func nucleiScan(ctx context.Context, r plugin.Runner, dir string, targets []string, level string, opts Options) ([]nucleiRow, string, error) {
	bin, err := r.Look("nuclei")
	if err != nil {
		return nil, "", err
	}
	lf, err := writeList(dir, "nuclei-targets.txt", targets)
	if err != nil {
		return nil, "", err
	}
	outPath := filepath.Join(dir, "nuclei-out.jsonl")

	rl := opts.RequestsPerSecond * 3
	if rl < 20 {
		rl = 20
	}
	if rl > 150 {
		rl = 150
	}

	argv := []string{
		bin, "-list", lf, "-jsonl", "-o", outPath,
		"-disable-update-check", "-no-color", "-silent",
		"-timeout", "5", "-retries", "0", "-c", "50",
		"-rate-limit", itoa(rl), "-stats", "-stats-interval", "30",
		"-max-time", nucleiMaxRuntime, // clean self-termination, flushes results
		// The genuinely unsafe template classes are always excluded.
		"-exclude-tags", "dos,intrusive,fuzz,fuzzing,brute,bruteforce",
		"-exclude-severity", "unknown",
		"-exclude-id", strings.Join(noisyTemplateIDs, ","),
		"-header", "User-Agent: " + userAgent,
	}
	dirs := vulnTemplateDirs[level]
	if len(dirs) == 0 {
		dirs = vulnTemplateDirs[VulnLevelSafeVerify]
	}
	tmplRoot := strings.TrimRight(opts.NucleiTemplatesDir, "/")
	for _, d := range dirs {
		if tmplRoot != "" {
			argv = append(argv, "-t", tmplRoot+"/"+d)
		} else {
			argv = append(argv, "-t", d)
		}
	}
	if level == VulnLevelPassive {
		argv = append(argv, "-no-interactsh")
	}
	// nuclei exits non-zero when it finds nothing / on partial errors; rely on
	// the output file instead of the exit code.
	stdout, code, execErr := r.Exec(ctx, argv)
	raw, _ := os.ReadFile(outPath)

	// jsonl results may land in the file or (older builds) on stdout.
	var rows []nucleiRow
	for _, blob := range []string{string(raw), stdout} {
		for _, ln := range strings.Split(blob, "\n") {
			ln = strings.TrimSpace(ln)
			if !strings.HasPrefix(ln, "{") {
				continue
			}
			var row nucleiRow
			if json.Unmarshal([]byte(ln), &row) == nil && row.TemplateID != "" {
				rows = append(rows, row)
			}
		}
	}
	warn := ""
	if len(rows) == 0 {
		warn = fmt.Sprintf("no findings (exit %d)", code)
		if execErr != nil {
			warn += " — " + execErr.Error()
		}
		if tail := lastLines(stripJSONLines(stdout), 4); tail != "" {
			warn += " — " + tail
		}
	}
	return rows, warn, nil
}

// stripJSONLines drops jsonl result/stat lines so an error tail is readable.
func stripJSONLines(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(ln); t != "" && !strings.HasPrefix(t, "{") {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func nucleiTemplatesVersion(ctx context.Context, r plugin.Runner) string {
	// the config file records it; fall back to the templates dir .version
	for _, p := range []string{
		os.ExpandEnv("$HOME/.config/nuclei/.templates-config.json"),
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg struct {
			Version string `json:"nuclei-templates-version"`
		}
		if json.Unmarshal(b, &cfg) == nil && cfg.Version != "" {
			return cfg.Version
		}
	}
	return ""
}

const userAgent = "Argus/0.1 (+authorized-assessment)"
