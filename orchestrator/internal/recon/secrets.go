package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/argus-platform/orchestrator/internal/plugin"
)

// Secret is a detected credential emitted as a "secret" event. The full value
// is shown to authorized operators (masking it defeats validation); the gateway
// additionally stores it encrypted at rest.
type Secret struct {
	DetectorType string `json:"detector_type"` // AWS, GitHub, JWT, PrivateKey, …
	Detector     string `json:"detector"`      // trufflehog | gitleaks | custom
	SourceKind   string `json:"source_kind"`   // js | repo | endpoint
	Source       string `json:"source"`        // URL or repo path
	Location     string `json:"location"`      // file:line
	Raw          string `json:"-"`             // internal alias of Value
	Value        string `json:"value"`         // the detected secret, unmasked
	Fingerprint  string `json:"fingerprint"`
	Verified     bool   `json:"verified"`
	Confidence   int    `json:"confidence"`
	Severity     string `json:"severity"`
}

func fingerprint(dtype, location, raw string) string {
	last4 := raw
	if len(raw) > 4 {
		last4 = raw[len(raw)-4:]
	}
	h := sha256.Sum256([]byte(dtype + "|" + location + "|" + last4))
	return hex.EncodeToString(h[:])
}

func sevFor(dtype string, verified bool) string {
	d := strings.ToLower(dtype)
	switch {
	case verified:
		return "critical"
	case strings.Contains(d, "privatekey"), strings.Contains(d, "aws"), strings.Contains(d, "gcp"),
		strings.Contains(d, "azure"), strings.Contains(d, "github"), strings.Contains(d, "gitlab"),
		strings.Contains(d, "stripe"), strings.Contains(d, "slack"), strings.Contains(d, "twilio"):
		return "high"
	case strings.Contains(d, "jwt"), strings.Contains(d, "generic"), strings.Contains(d, "basicauth"):
		return "medium"
	default:
		return "medium"
	}
}

// ── trufflehog ────────────────────────────────────────────────────────────

type thResult struct {
	DetectorName   string `json:"DetectorName"`
	Raw            string `json:"Raw"`
	Redacted       string `json:"Redacted"`
	Verified       bool   `json:"Verified"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

func trufflehogFile(ctx context.Context, r plugin.Runner, path, sourceLabel string) []Secret {
	bin, err := r.Look("trufflehog")
	if err != nil {
		return nil
	}
	out, _, err := r.Exec(ctx, []string{
		bin, "filesystem", path, "--json", "--no-update", "--no-verification",
	})
	if err != nil {
		return nil
	}
	var found []Secret
	for _, ln := range jsonLines(out) {
		var t thResult
		if json.Unmarshal(ln, &t) != nil || t.Raw == "" {
			continue
		}
		loc := locLabel(sourceLabel, t.SourceMetadata.Data.Filesystem.File, t.SourceMetadata.Data.Filesystem.Line)
		found = append(found, newSecret(t.DetectorName, "trufflehog", loc, t.Raw, t.Verified))
	}
	return found
}

// locLabel builds a "<file>:<line>" location. When the scanner reports the file
// it scanned, the basename is used (so a batch scan of one directory can be
// mapped back to the per-file source URL); otherwise the caller's label is.
func locLabel(sourceLabel, file string, line int) string {
	base := sourceLabel
	if file != "" {
		base = filepath.Base(file)
	}
	if line > 0 {
		return base + ":" + strconv.Itoa(line)
	}
	return base
}

// ── gitleaks ──────────────────────────────────────────────────────────────

type glResult struct {
	RuleID    string `json:"RuleID"`
	Secret    string `json:"Secret"`
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	Match     string `json:"Match"`
}

func gitleaksDir(ctx context.Context, r plugin.Runner, dir, sourceLabel string) []Secret {
	bin, err := r.Look("gitleaks")
	if err != nil {
		return nil
	}
	reportPath := filepath.Join(dir, "gitleaks-report.json")
	_, _, _ = r.Exec(ctx, []string{
		bin, "detect", "--source", dir, "--no-git", "--redact=0",
		"--report-format", "json", "--report-path", reportPath, "--exit-code", "0",
	})
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return nil
	}
	var rows []glResult
	if json.Unmarshal(raw, &rows) != nil {
		return nil
	}
	var found []Secret
	for _, g := range rows {
		if g.Secret == "" {
			continue
		}
		loc := locLabel(sourceLabel, g.File, g.StartLine)
		found = append(found, newSecret(g.RuleID, "gitleaks", loc, g.Secret, false))
	}
	return found
}

// ── custom detectors (things scanners often miss in minified JS) ───────────

var customDetectors = []struct {
	name string
	re   *regexp.Regexp
}{
	{"GoogleAPIKey", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"SlackToken", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,72}`)},
	{"StripeSecretKey", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"GitHubToken", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"AWSAccessKeyID", regexp.MustCompile(`A(KIA|SIA|IDA|ROA)[0-9A-Z]{16}`)},
	{"PrivateKeyBlock", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"FirebaseURL", regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`)},
}

func customScan(content, sourceLabel string) []Secret {
	var found []Secret
	seen := map[string]bool{}
	for _, d := range customDetectors {
		for _, m := range d.re.FindAllString(content, 10) {
			if seen[d.name+m] {
				continue
			}
			seen[d.name+m] = true
			found = append(found, newSecret(d.name, "custom", sourceLabel, m, false))
		}
	}
	return found
}

func newSecret(dtype, detector, location, raw string, verified bool) Secret {
	conf := 55
	if detector == "trufflehog" {
		conf = 75
	}
	if verified {
		conf = 99
	}
	return Secret{
		DetectorType: dtype, Detector: detector, Location: location,
		Raw: raw, Value: raw, Fingerprint: fingerprint(dtype, location, raw),
		Verified: verified, Confidence: conf, Severity: sevFor(dtype, verified),
	}
}

// scanBlob writes content to a temp file and runs every detector over it.
func scanBlob(ctx context.Context, r plugin.Runner, dir, content, sourceLabel string) []Secret {
	sub, err := os.MkdirTemp(dir, "blob-*")
	if err != nil {
		return customScan(content, sourceLabel)
	}
	defer os.RemoveAll(sub)
	f := filepath.Join(sub, "content.txt")
	if os.WriteFile(f, []byte(content), 0o600) != nil {
		return customScan(content, sourceLabel)
	}
	var out []Secret
	out = append(out, trufflehogFile(ctx, r, f, sourceLabel)...)
	out = append(out, gitleaksDir(ctx, r, sub, sourceLabel)...)
	out = append(out, customScan(content, sourceLabel)...)
	return dedupeSecrets(out)
}

func dedupeSecrets(s []Secret) []Secret {
	seen := map[string]bool{}
	var out []Secret
	for _, x := range s {
		if seen[x.Fingerprint] {
			continue
		}
		seen[x.Fingerprint] = true
		out = append(out, x)
	}
	return out
}
