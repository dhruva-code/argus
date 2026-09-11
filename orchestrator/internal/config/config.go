// Package config loads orchestrator settings from the environment.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	RedisURL           string
	GatewayURL         string
	InternalToken      string
	WorkerConcurrency  int
	HeartbeatSeconds   int
	ToolsBinDir        string
	SSRFAllowCIDRs     []string
	SSRFBlockMetadata  bool
	LogLevel           string
	WordlistsDir       string
	FfufWordlist       string // basename inside WordlistsDir
	GitHubToken        string
	NucleiTemplatesDir string // root of the nuclei-templates checkout
	NaabuPortSpec      string // "" | "top-100" | "top-1000" | explicit list
	// Injection Testing Engine
	MaxInjectionParams int    // per-scan cap on distinct parameters tested
	OASTCollectorURL   string // public base URL the TARGET can reach for SSRF/RFI callbacks; "" disables those classes
	XSSBrowserVerify   bool   // attempt headless-browser XSS confirmation when a Node binary is available
}

func Load() Config {
	return Config{
		RedisURL:           env("REDIS_URL", "redis://localhost:6379/0"),
		GatewayURL:         env("ORCH_GATEWAY_URL", "http://localhost:8000"),
		InternalToken:      env("ORCH_INTERNAL_TOKEN", ""),
		WorkerConcurrency:  envInt("ORCH_WORKER_CONCURRENCY", 4),
		HeartbeatSeconds:   envInt("ORCH_HEARTBEAT_SECONDS", 10),
		ToolsBinDir:        env("ARGUS_TOOLS_BIN_DIR", ""),
		SSRFAllowCIDRs:     envList("SSRF_ALLOW_CIDRS"),
		SSRFBlockMetadata:  env("SSRF_BLOCK_METADATA", "true") == "true",
		LogLevel:           env("ARGUS_LOG_LEVEL", "info"),
		WordlistsDir:       env("ARGUS_WORDLISTS_DIR", ""),
		FfufWordlist:       env("ARGUS_FFUF_WORDLIST", "raft-small-directories.txt"),
		GitHubToken:        env("GITHUB_TOKEN", ""),
		NucleiTemplatesDir: env("ARGUS_NUCLEI_TEMPLATES_DIR", ""),
		NaabuPortSpec:      env("ARGUS_NAABU_PORTS", ""),
		MaxInjectionParams: envInt("ARGUS_MAX_INJECTION_PARAMS", 60),
		OASTCollectorURL:   env("ARGUS_OAST_COLLECTOR_URL", ""),
		XSSBrowserVerify:   env("ARGUS_XSS_BROWSER_VERIFY", "true") == "true",
	}
}

// WordlistPath returns the absolute path to the configured ffuf wordlist, or ""
// when no wordlists directory is set.
func (c Config) WordlistPath() string {
	if c.WordlistsDir == "" {
		return ""
	}
	return filepath.Join(c.WordlistsDir, c.FfufWordlist)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envList(k string) []string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
