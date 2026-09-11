// Package tools holds the built-in tool plugins and a registry to look them up.
package tools

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/argus-platform/orchestrator/internal/plugin"
)

// cliTool is a generic plugin for tools that print a version string when passed
// a version flag. Every ProjectDiscovery tool and ffuf fit this shape.
type cliTool struct {
	meta         plugin.Metadata
	versionRe    *regexp.Regexp
	presenceOnly bool // tool has no version flag — healthy if the binary resolves
}

func (c cliTool) Metadata() plugin.Metadata { return c.meta }

func (c cliTool) DetectVersion(ctx context.Context, r plugin.Runner) (string, error) {
	path, err := r.Look(c.meta.Binary)
	if err != nil {
		return "", err
	}
	argv := append([]string{path}, c.meta.VersionArgs...)
	out, _, err := r.Exec(ctx, argv)
	if err != nil {
		return "", err
	}
	if m := c.versionRe.FindStringSubmatch(out); len(m) > 1 {
		return m[1], nil
	}
	// Fall back to a bare semver anywhere in the output (some tools print only
	// the number). A non-version banner yields "" -> caller marks it degraded.
	if m := semverRe.FindString(out); m != "" {
		return strings.TrimPrefix(m, "v"), nil
	}
	return "", nil
}

func (c cliTool) Health(ctx context.Context, r plugin.Runner) plugin.Health {
	start := time.Now()
	h := plugin.Health{CheckedAt: start.UTC()}
	path, err := r.Look(c.meta.Binary)
	if err != nil {
		h.State = plugin.HealthMissing
		h.Detail = "binary not found: " + c.meta.Binary
		return h
	}
	h.Path = path
	if c.presenceOnly {
		h.LatencyMS = time.Since(start).Milliseconds()
		h.State = plugin.HealthOK
		h.Detail = "installed (no version command)"
		return h
	}
	v, err := c.DetectVersion(ctx, r)
	h.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		h.State = plugin.HealthDegraded
		h.Detail = "version probe failed: " + err.Error()
		return h
	}
	h.InstalledVersion = v
	if v == "" {
		h.State = plugin.HealthDegraded
		h.Detail = "installed but version could not be parsed"
		return h
	}
	if c.meta.MinVersion != "" && compareVersions(v, c.meta.MinVersion) < 0 {
		h.State = plugin.HealthDegraded
		h.Detail = "version " + v + " is below supported minimum " + c.meta.MinVersion
		return h
	}
	h.State = plugin.HealthOK
	h.Detail = "ok"
	return h
}

var semverRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// compareVersions does a lenient semver-ish comparison. Returns -1, 0, or 1.
func compareVersions(a, b string) int {
	pa, pb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return strings.Compare(a, b)
	}
	for i := 1; i <= 3; i++ {
		x, y := atoi(pa[i]), atoi(pb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

// Registry indexes the built-in plugins by tool name.
type Registry struct {
	byName map[string]plugin.Tool
}

func BuiltIn() *Registry {
	reg := &Registry{byName: map[string]plugin.Tool{}}
	for _, t := range builtinTools() {
		reg.byName[t.Metadata().Name] = t
	}
	return reg
}

func (r *Registry) Get(name string) (plugin.Tool, bool) {
	t, ok := r.byName[name]
	return t, ok
}

func (r *Registry) All() []plugin.Tool {
	out := make([]plugin.Tool, 0, len(r.byName))
	for _, t := range r.byName {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata().Name < out[j].Metadata().Name })
	return out
}

func pdVersionRe() *regexp.Regexp {
	// ProjectDiscovery tools print: "Current Version: v2.6.3" (to stderr).
	return regexp.MustCompile(`(?i)current version:\s*v?([0-9][^\s]*)`)
}

func builtinTools() []plugin.Tool {
	return []plugin.Tool{
		cliTool{versionRe: pdVersionRe(), meta: plugin.Metadata{
			Name: "subfinder", DisplayName: "Subfinder", Binary: "subfinder",
			Homepage:    "https://github.com/projectdiscovery/subfinder",
			Docs:        "https://docs.projectdiscovery.io/tools/subfinder",
			VersionArgs: []string{"-version"}, MinVersion: "2.6.0", TestedVersion: "2.16.0",
			Capabilities: []plugin.Capability{plugin.CapSubdomainEnum},
			Safety:       plugin.SafetyPassive, NeedsAPIKey: false,
			InstallHint: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		}},
		cliTool{versionRe: pdVersionRe(), meta: plugin.Metadata{
			Name: "dnsx", DisplayName: "DNSX", Binary: "dnsx",
			Homepage:    "https://github.com/projectdiscovery/dnsx",
			Docs:        "https://docs.projectdiscovery.io/tools/dnsx",
			VersionArgs: []string{"-version"}, MinVersion: "1.2.0", TestedVersion: "1.3.1",
			Capabilities: []plugin.Capability{plugin.CapDNSResolve},
			Safety:       plugin.SafetyLow,
			InstallHint:  "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		}},
		cliTool{versionRe: pdVersionRe(), meta: plugin.Metadata{
			Name: "httpx", DisplayName: "HTTPX", Binary: "httpx",
			Homepage:    "https://github.com/projectdiscovery/httpx",
			Docs:        "https://docs.projectdiscovery.io/tools/httpx",
			VersionArgs: []string{"-version"}, MinVersion: "1.3.0", TestedVersion: "1.11.0",
			Capabilities: []plugin.Capability{plugin.CapHTTPProbe},
			Safety:       plugin.SafetyLow,
			InstallHint:  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
		}},
		cliTool{versionRe: pdVersionRe(), meta: plugin.Metadata{
			Name: "katana", DisplayName: "Katana", Binary: "katana",
			Homepage:    "https://github.com/projectdiscovery/katana",
			Docs:        "https://docs.projectdiscovery.io/tools/katana",
			VersionArgs: []string{"-version"}, MinVersion: "1.0.0", TestedVersion: "1.7.0",
			Capabilities: []plugin.Capability{plugin.CapCrawl},
			Safety:       plugin.SafetyActive,
			InstallHint:  "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
		}},
		cliTool{versionRe: pdVersionRe(), meta: plugin.Metadata{
			Name: "nuclei", DisplayName: "Nuclei", Binary: "nuclei",
			Homepage:    "https://github.com/projectdiscovery/nuclei",
			Docs:        "https://docs.projectdiscovery.io/tools/nuclei",
			VersionArgs: []string{"-version"}, MinVersion: "3.0.0", TestedVersion: "3.11.1",
			Capabilities: []plugin.Capability{plugin.CapVulnScan},
			Safety:       plugin.SafetyActive,
			InstallHint:  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		}},
		cliTool{versionRe: pdVersionRe(), meta: plugin.Metadata{
			Name: "naabu", DisplayName: "Naabu", Binary: "naabu",
			Homepage:    "https://github.com/projectdiscovery/naabu",
			Docs:        "https://docs.projectdiscovery.io/tools/naabu",
			VersionArgs: []string{"-version"}, MinVersion: "2.1.0", TestedVersion: "2.6.1",
			Capabilities: []plugin.Capability{plugin.CapPortScan},
			Safety:       plugin.SafetyActive,
			InstallHint:  "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		}},
		cliTool{versionRe: regexp.MustCompile(`ffuf version:?\s*v?([0-9][^\s]*)`), meta: plugin.Metadata{
			Name: "ffuf", DisplayName: "ffuf", Binary: "ffuf",
			Homepage:    "https://github.com/ffuf/ffuf",
			Docs:        "https://github.com/ffuf/ffuf/wiki",
			VersionArgs: []string{"-V"}, MinVersion: "2.0.0", TestedVersion: "2.1.0",
			Capabilities: []plugin.Capability{plugin.CapContentDiscover},
			Safety:       plugin.SafetyActive,
			InstallHint:  "go install github.com/ffuf/ffuf/v2@latest",
		}},
		cliTool{versionRe: regexp.MustCompile(`(?i)version:?\s*v?([0-9][^\s]*)`), meta: plugin.Metadata{
			Name: "gau", DisplayName: "gau (GetAllUrls)", Binary: "gau",
			Homepage:    "https://github.com/lc/gau",
			Docs:        "https://github.com/lc/gau",
			VersionArgs: []string{"--version"}, MinVersion: "2.0.0", TestedVersion: "2.2.4",
			Capabilities: []plugin.Capability{plugin.CapHistoricalURLs},
			Safety:       plugin.SafetyPassive,
			InstallHint:  "go install github.com/lc/gau/v2/cmd/gau@latest",
		}},
		cliTool{presenceOnly: true, versionRe: semverRe, meta: plugin.Metadata{
			Name: "assetfinder", DisplayName: "assetfinder", Binary: "assetfinder",
			Homepage:   "https://github.com/tomnomnom/assetfinder",
			Docs:       "https://github.com/tomnomnom/assetfinder",
			MinVersion: "", TestedVersion: "0.1.1",
			Capabilities: []plugin.Capability{plugin.CapSubdomainEnum},
			Safety:       plugin.SafetyPassive,
			InstallHint:  "go install github.com/tomnomnom/assetfinder@latest",
		}},
		cliTool{versionRe: regexp.MustCompile(`trufflehog\s+v?([0-9][^\s]*)`), meta: plugin.Metadata{
			Name: "trufflehog", DisplayName: "TruffleHog", Binary: "trufflehog",
			Homepage:    "https://github.com/trufflesecurity/trufflehog",
			Docs:        "https://github.com/trufflesecurity/trufflehog",
			VersionArgs: []string{"--version"}, MinVersion: "3.60.0", TestedVersion: "3.97.4",
			Capabilities: []plugin.Capability{plugin.CapSecretScan},
			Safety:       plugin.SafetyPassive,
			InstallHint:  "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh",
		}},
		cliTool{versionRe: semverRe, meta: plugin.Metadata{
			Name: "gitleaks", DisplayName: "Gitleaks", Binary: "gitleaks",
			Homepage:    "https://github.com/gitleaks/gitleaks",
			Docs:        "https://github.com/gitleaks/gitleaks",
			VersionArgs: []string{"version"}, MinVersion: "8.0.0", TestedVersion: "8.30.1",
			Capabilities: []plugin.Capability{plugin.CapSecretScan},
			Safety:       plugin.SafetyPassive,
			InstallHint:  "download from https://github.com/gitleaks/gitleaks/releases",
		}},
		cliTool{versionRe: regexp.MustCompile(`Nmap version\s+v?([0-9][^\s]*)`), meta: plugin.Metadata{
			Name: "nmap", DisplayName: "Nmap", Binary: "nmap",
			Homepage:    "https://nmap.org",
			Docs:        "https://nmap.org/book/man.html",
			VersionArgs: []string{"--version"}, MinVersion: "7.0.0", TestedVersion: "7.98",
			Capabilities: []plugin.Capability{plugin.CapPortScan},
			Safety:       plugin.SafetyActive,
			InstallHint:  "apt-get install nmap  (or https://nmap.org/download.html)",
		}},
	}
}
