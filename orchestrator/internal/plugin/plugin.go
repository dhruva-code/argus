// Package plugin defines the generic security-tool plugin interface. Every
// external tool (subfinder, dnsx, httpx, katana, nuclei, ffuf, naabu, …) is
// represented as a plugin implementing this contract. Tool execution is never
// hard-coded elsewhere in the codebase.
package plugin

import (
	"context"
	"time"
)

// SafetyClass classifies how intrusive a tool is, mirroring the three-level
// model in the spec (§8 Phase 12).
type SafetyClass string

const (
	SafetyPassive SafetyClass = "passive" // no request to target infra
	SafetyLow     SafetyClass = "low"     // low-impact confirmation requests
	SafetyActive  SafetyClass = "active"  // higher-volume active probing
)

// Capability is a coarse tag for what a tool produces, used to wire tools into
// pipeline phases.
type Capability string

const (
	CapSubdomainEnum   Capability = "subdomain_enum"
	CapDNSResolve      Capability = "dns_resolve"
	CapHTTPProbe       Capability = "http_probe"
	CapCrawl           Capability = "crawl"
	CapPortScan        Capability = "port_scan"
	CapVulnScan        Capability = "vuln_scan"
	CapContentDiscover Capability = "content_discovery"
	CapHistoricalURLs  Capability = "historical_urls"
	CapSecretScan      Capability = "secret_scan"
)

// Metadata is the static description of a tool.
type Metadata struct {
	Name          string       `json:"name"`
	DisplayName   string       `json:"display_name"`
	Homepage      string       `json:"homepage"`
	Docs          string       `json:"docs"`
	Binary        string       `json:"binary"`         // expected executable name
	VersionArgs   []string     `json:"version_args"`   // e.g. ["-version"]
	MinVersion    string       `json:"min_version"`    // lowest version known-good
	TestedVersion string       `json:"tested_version"` // version this integration was validated against
	Capabilities  []Capability `json:"capabilities"`
	Safety        SafetyClass  `json:"safety"`
	NeedsAPIKey   bool         `json:"needs_api_key"`
	InstallHint   string       `json:"install_hint"`
}

// HealthState is the outcome of a health check.
type HealthState string

const (
	HealthOK       HealthState = "ok"
	HealthDegraded HealthState = "degraded"
	HealthMissing  HealthState = "missing"
	HealthUnknown  HealthState = "unknown"
)

// Health is a point-in-time report on one tool.
type Health struct {
	State            HealthState `json:"state"`
	InstalledVersion string      `json:"installed_version"`
	Path             string      `json:"path"`
	Detail           string      `json:"detail"`
	CheckedAt        time.Time   `json:"checked_at"`
	LatencyMS        int64       `json:"latency_ms"`
}

// RunResult is the normalized output of a tool run. Milestone 1 does not run
// tools against targets, but the type is defined here so phase plugins in later
// milestones implement a stable contract.
type RunResult struct {
	Tool         string           `json:"tool"`
	Version      string           `json:"version"`
	ExitCode     int              `json:"exit_code"`
	StartedAt    time.Time        `json:"started_at"`
	FinishedAt   time.Time        `json:"finished_at"`
	RawArtifact  string           `json:"raw_artifact"` // object-storage key of raw stdout
	Records      []map[string]any `json:"records"`      // parsed, normalized rows
	RequestCount int              `json:"request_count"`
	Errors       []string         `json:"errors"`
}

// Tool is the plugin contract.
type Tool interface {
	Metadata() Metadata
	// DetectVersion runs the binary's version command and returns the parsed
	// version string.
	DetectVersion(ctx context.Context, r Runner) (string, error)
	// Health performs a fast liveness/sanity check.
	Health(ctx context.Context, r Runner) Health
}

// Runner abstracts process execution so tests can inject a fake and so every
// real invocation goes through one audited, argv-only path (never shell).
type Runner interface {
	// Look resolves a binary to an absolute path (tools bin dir, then $PATH).
	Look(binary string) (string, error)
	// Exec runs argv[0] with argv[1:] and returns combined output. No shell.
	Exec(ctx context.Context, argv []string) (stdout string, exitCode int, err error)
}
