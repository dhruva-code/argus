package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/argus-platform/orchestrator/internal/jobs"
	"github.com/argus-platform/orchestrator/internal/queue"
	"github.com/argus-platform/orchestrator/internal/recon"
	"github.com/argus-platform/orchestrator/internal/scope"
)

// RunContext is passed to every job handler.
type RunContext struct {
	Job    *jobs.Job
	Engine *Engine
	Ctx    context.Context
}

func (rc *RunContext) log(level, msg string) {
	rc.Engine.emit(rc.Job, queue.Event{Type: "log", Level: level, Message: msg})
}

func (rc *RunContext) result(data map[string]any, msg string) {
	rc.Engine.emit(rc.Job, queue.Event{Type: "result", Level: "RESULT", Message: msg, Data: data})
}

func (rc *RunContext) cancelled() bool { return rc.Ctx.Err() != nil }

type handlerFunc func(*RunContext) (jobs.Status, error)

var handlers = map[jobs.Type]handlerFunc{
	jobs.TypeToolHealth:    handleToolHealth,
	jobs.TypeScopeSelfTest: handleScopeSelfTest,
	jobs.TypeReconScan:     handleReconScan,
}

func structToMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func stringList(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// handleReconScan runs the M2 discovery pipeline (passive enum → active resolve
// → alive-host detection) and streams normalized assets + edges back for the
// gateway's Asset Identity Engine to upsert.
func handleReconScan(rc *RunContext) (jobs.Status, error) {
	e := rc.Engine
	eng, err := scope.Compile(rc.Job.ScopePolicy)
	if err != nil {
		return jobs.StatusFailed, fmt.Errorf("scope policy did not compile: %w", err)
	}

	roots := stringList(rc.Job.Params["roots"])
	phases := stringList(rc.Job.Params["phases"])
	if len(roots) == 0 {
		return jobs.StatusFailed, fmt.Errorf("no root domains — the project scope has no domain/subdomain/wildcard allow rule")
	}
	if len(phases) == 0 {
		phases = []string{recon.PhasePassiveEnum, recon.PhaseActiveEnum, recon.PhaseMergeAlive}
	}

	rl := rc.Job.RateLimits
	opts := recon.Options{
		Roots:              roots,
		Phases:             phases,
		RequestsPerSecond:  rl.RequestsPerSecond,
		DNSPerSecond:       rl.DNSPerSecond,
		MaxTargets:         rl.MaxTargets,
		BruteWords:         stringList(rc.Job.Params["brute_words"]),
		WordlistPath:       e.cfg.WordlistPath(),
		GitHubToken:        e.cfg.GitHubToken,
		GitHubOrgs:         stringList(rc.Job.Params["github_orgs"]),
		PortSpec:           firstNonEmpty(str(rc.Job.Params["port_spec"]), e.cfg.NaabuPortSpec),
		ServiceDetection:   boolParam(rc.Job.Params["service_detection"], true),
		VulnLevel:          str(rc.Job.Params["vuln_level"]),
		MaxVulnTargets:     toInt(rc.Job.Params["max_vuln_targets"]),
		NucleiTemplatesDir: e.cfg.NucleiTemplatesDir,
		MaxInjectionParams: e.cfg.MaxInjectionParams,
		InjectionSSRF:      boolParam(rc.Job.Params["ssrf_ack"], false),
		OASTCollectorURL:   e.cfg.OASTCollectorURL,
		OASTStatusURL:      e.cfg.GatewayURL,
		OASTInternalToken:  e.cfg.InternalToken,
		ProjectID:          rc.Job.ProjectID,
	}
	if e.cfg.XSSBrowserVerify {
		opts.BrowserBinary = recon.LookBrowserBinary()
	}
	if profID := str(rc.Job.Params["auth_profile_id"]); profID != "" {
		if name, val, err := e.fetchAuthProfile(rc.Ctx, profID); err == nil {
			opts.AuthHeaderName, opts.AuthHeaderValue = name, val
		} else {
			rc.log("WARNING", "auth profile could not be loaded — testing unauthenticated: "+err.Error())
		}
	}
	opts.SetMaxResponseBytes(rl.MaxResponseBytes)

	assets, edges, vhosts, endpoints, secrets, repos, ports, findings, injPoints := 0, 0, 0, 0, 0, 0, 0, 0, 0
	cb := recon.Callbacks{
		Log: func(level, msg string) { rc.log(level, msg) },
		Asset: func(a recon.Asset) {
			assets++
			e.emit(rc.Job, queue.Event{
				Type: "asset", Level: "RESULT", Data: structToMap(a),
				Message: fmt.Sprintf("%s %s [%s]", a.Type, a.Value, a.Status),
			})
		},
		Edge: func(ed recon.Edge) {
			edges++
			e.emit(rc.Job, queue.Event{Type: "asset_edge", Data: structToMap(ed)})
		},
		VHost: func(v recon.VHost) {
			vhosts++
			e.emit(rc.Job, queue.Event{
				Type: "vhost", Level: "RESULT", Data: structToMap(v),
				Message: fmt.Sprintf("vhost %s on %s [%s]", v.Hostname, v.IP, v.Classification),
			})
		},
		Endpoint: func(ep recon.Endpoint) {
			endpoints++
			e.emit(rc.Job, queue.Event{
				Type: "endpoint", Level: "RESULT", Data: structToMap(ep),
				Message: fmt.Sprintf("%s %s", ep.Method, ep.NormalizedURL),
			})
		},
		Secret: func(s recon.Secret) {
			secrets++
			e.emit(rc.Job, queue.Event{
				Type: "secret", Level: "WARNING", Data: structToMap(s),
				Message: fmt.Sprintf("secret candidate: %s at %s", s.DetectorType, s.Location),
			})
		},
		Repo: func(rp recon.Repository) {
			repos++
			e.emit(rc.Job, queue.Event{
				Type: "repository", Level: "RESULT", Data: structToMap(rp),
				Message: "repo " + rp.FullName,
			})
		},
		Port: func(p recon.Port) {
			ports++
			e.emit(rc.Job, queue.Event{
				Type: "port", Level: "RESULT", Data: structToMap(p),
				Message: fmt.Sprintf("open %s:%d %s", p.IP, p.Port, p.Service),
			})
		},
		Finding: func(f recon.Finding) {
			findings++
			lvl := "WARNING"
			if f.Severity == "info" || f.Severity == "low" {
				lvl = "INFO"
			}
			e.emit(rc.Job, queue.Event{
				Type: "finding", Level: lvl, Data: structToMap(f),
				Message: fmt.Sprintf("%s finding: %s at %s", f.Severity, f.TemplateID, f.MatchedAt),
			})
		},
		InjPoint: func(ip recon.InjPointRecord) {
			injPoints++
			lvl := "INFO"
			if strings.Contains(ip.BestResult, string(recon.TierLikely)) || strings.Contains(ip.BestResult, string(recon.TierVerified)) {
				lvl = "WARNING"
			}
			e.emit(rc.Job, queue.Event{
				Type: "injection_point", Level: lvl, Data: structToMap(ip),
				Message: fmt.Sprintf("%s %s param=%s [%s]", ip.Method, ip.URL, ip.ParamName, ip.BestResult),
			})
		},
		Checkpoint: func(phase string, data map[string]any) {
			_ = e.q.SaveCheckpoint(context.Background(), rc.Job.ID, map[string]any{"phase": phase, "data": data})
			rc.log("DEBUG", "checkpoint: "+phase)
		},
		Cancelled: func() bool { return rc.cancelled() },
	}

	res, err := recon.Run(rc.Ctx, eng, e.guard, e.runner, opts, cb)
	if err != nil {
		e.emit(rc.Job, queue.Event{Type: "error", Level: "ERROR", Message: err.Error()})
	}
	rc.result(map[string]any{
		"discovered": res.Discovered, "in_scope": res.InScope,
		"resolved": res.Resolved, "alive": res.Alive, "endpoints": res.Endpoints,
		"secrets": res.Secrets, "sensitive_paths": res.SensitivePaths, "repos": res.Repos,
		"ports": res.Ports, "findings": res.Findings, "injection_points": res.InjectionPoints,
		"assets_emitted": assets, "edges_emitted": edges, "vhosts_emitted": vhosts,
		"endpoints_emitted": endpoints, "secrets_emitted": secrets, "repos_emitted": repos,
		"ports_emitted": ports, "findings_emitted": findings, "injection_points_emitted": injPoints,
		"phases": res.Phases,
	}, fmt.Sprintf("recon: %d assets / %d alive / %d endpoints / %d secrets / %d ports / %d findings / %d injection points",
		res.Discovered, res.Alive, res.Endpoints, secrets, ports, findings, res.InjectionPoints))

	if rc.cancelled() {
		return jobs.StatusCancelled, nil
	}
	if err != nil {
		return jobs.StatusPartiallyCompleted, nil
	}
	return jobs.StatusCompleted, nil
}

// handleToolHealth probes each requested tool plugin for presence, version, and
// basic health. It writes one result event per tool; the gateway persists these
// to tool_integrations / tool_versions.
func handleToolHealth(rc *RunContext) (jobs.Status, error) {
	e := rc.Engine
	names, _ := rc.Job.Params["tools"].([]any)
	var targets []string
	for _, n := range names {
		if s, ok := n.(string); ok {
			targets = append(targets, s)
		}
	}
	if len(targets) == 0 {
		for _, t := range e.reg.All() {
			targets = append(targets, t.Metadata().Name)
		}
	}

	rc.log("INFO", fmt.Sprintf("probing %d tool(s)", len(targets)))
	ok, degraded, missing := 0, 0, 0
	ctx := rc.Ctx

	for _, name := range targets {
		if rc.cancelled() {
			return jobs.StatusCancelled, nil
		}
		tool, found := e.reg.Get(name)
		if !found {
			missing++
			rc.result(map[string]any{"tool": name, "state": "missing", "detail": "unknown tool"}, name+": unknown tool")
			continue
		}
		h := tool.Health(ctx, e.runner)
		md := tool.Metadata()
		rc.result(map[string]any{
			"tool":              name,
			"display_name":      md.DisplayName,
			"state":             string(h.State),
			"installed_version": h.InstalledVersion,
			"tested_version":    md.TestedVersion,
			"min_version":       md.MinVersion,
			"path":              h.Path,
			"detail":            h.Detail,
			"latency_ms":        h.LatencyMS,
			"capabilities":      md.Capabilities,
			"safety":            md.Safety,
			"needs_api_key":     md.NeedsAPIKey,
			"install_hint":      md.InstallHint,
			"checked_at":        h.CheckedAt.Format(time.RFC3339),
		}, fmt.Sprintf("%s: %s (%s)", name, h.State, h.InstalledVersion))
		switch h.State {
		case "ok":
			ok++
		case "degraded":
			degraded++
		default:
			missing++
		}
	}

	rc.log("INFO", fmt.Sprintf("health check complete: %d ok, %d degraded, %d missing", ok, degraded, missing))
	if missing > 0 || degraded > 0 {
		return jobs.StatusPartiallyCompleted, nil
	}
	return jobs.StatusCompleted, nil
}

// handleScopeSelfTest compiles the job's scope policy and evaluates a set of
// sample targets, emitting the decision for each. Purely local; no network.
func handleScopeSelfTest(rc *RunContext) (jobs.Status, error) {
	eng, err := scope.Compile(rc.Job.ScopePolicy)
	if err != nil {
		return jobs.StatusFailed, fmt.Errorf("scope policy did not compile: %w", err)
	}
	raw, _ := rc.Job.Params["targets"].([]any)
	if len(raw) == 0 {
		rc.log("WARNING", "no targets supplied")
		return jobs.StatusCompleted, nil
	}
	allowed, denied := 0, 0
	for _, item := range raw {
		if rc.cancelled() {
			return jobs.StatusCancelled, nil
		}
		m, _ := item.(map[string]any)
		t := scope.Target{
			Host: str(m["host"]),
			IP:   str(m["ip"]),
			Path: str(m["path"]),
			ASN:  str(m["asn"]),
			Port: toInt(m["port"]),
		}
		d := eng.Evaluate(t)
		if d.Allowed {
			allowed++
		} else {
			denied++
		}
		rc.result(map[string]any{
			"target":  m,
			"allowed": d.Allowed,
			"rule_id": d.RuleID,
			"reason":  d.Reason,
		}, fmt.Sprintf("%v -> allowed=%v (%s)", m, d.Allowed, d.Reason))
	}
	rc.log("INFO", fmt.Sprintf("scope self-test: %d in scope, %d out of scope", allowed, denied))
	return jobs.StatusCompleted, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func boolParam(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}
