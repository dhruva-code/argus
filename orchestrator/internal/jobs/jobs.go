// Package jobs defines the job contract shared between the gateway (producer)
// and the orchestrator (consumer), plus the lifecycle state machine.
package jobs

import (
	"time"

	"github.com/argus-platform/orchestrator/internal/scope"
)

type Status string

const (
	StatusQueued             Status = "queued"
	StatusRunning            Status = "running"
	StatusPaused             Status = "paused"
	StatusCompleted          Status = "completed"
	StatusFailed             Status = "failed"
	StatusCancelled          Status = "cancelled"
	StatusPartiallyCompleted Status = "partially_completed"
)

// Terminal reports whether a status is final (no further transitions).
func (s Status) Terminal() bool {
	switch s {
	case StatusCompleted, StatusFailed, StatusCancelled, StatusPartiallyCompleted:
		return true
	default:
		return false
	}
}

// CanTransition encodes the allowed status transitions. The orchestrator refuses
// any transition not listed here, so a stale control message cannot, for
// example, resurrect a cancelled job.
func CanTransition(from, to Status) bool {
	allowed := map[Status][]Status{
		StatusQueued:  {StatusRunning, StatusCancelled},
		StatusRunning: {StatusPaused, StatusCompleted, StatusFailed, StatusCancelled, StatusPartiallyCompleted},
		StatusPaused:  {StatusRunning, StatusCancelled},
	}
	for _, s := range allowed[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Type is the kind of work a job performs. Milestone 1 ships the two
// non-networked types; recon/scan phase types arrive in later milestones.
type Type string

const (
	TypeToolHealth    Type = "tool.health"    // probe tool binaries: version + health
	TypeScopeSelfTest Type = "scope.selftest" // evaluate sample targets against the policy
	TypeReconScan     Type = "recon.scan"     // M2: passive+active subdomain enum, resolve, alive-host detection
)

// Job is the unit of work pulled from the queue. The gateway serializes it as
// JSON onto the Redis list; the orchestrator deserializes and runs it. The
// compiled scope policy travels with the job so the worker never needs a
// callback to decide what is in scope.
type Job struct {
	ID          string         `json:"id"`
	ProjectID   string         `json:"project_id"`
	OrgID       string         `json:"org_id"`
	Type        Type           `json:"type"`
	Params      map[string]any `json:"params"`
	ScopePolicy scope.Policy   `json:"scope_policy"`
	RateLimits  RateLimits     `json:"rate_limits"`
	EnqueuedAt  time.Time      `json:"enqueued_at"`
	Checkpoint  map[string]any `json:"checkpoint,omitempty"`
}

// RateLimits are the conservative-by-default resource controls every phase must
// honor (see spec §31).
type RateLimits struct {
	Concurrency       int `json:"concurrency"`
	RequestsPerSecond int `json:"requests_per_second"`
	DNSPerSecond      int `json:"dns_per_second"`
	TimeoutSeconds    int `json:"timeout_seconds"`
	Retries           int `json:"retries"`
	MaxTargets        int `json:"max_targets"`
	MaxResponseBytes  int `json:"max_response_bytes"`
}

// DefaultRateLimits returns the conservative defaults applied when a scan
// profile does not override them.
func DefaultRateLimits() RateLimits {
	return RateLimits{
		Concurrency: 5, RequestsPerSecond: 10, DNSPerSecond: 20,
		TimeoutSeconds: 15, Retries: 2, MaxTargets: 5000, MaxResponseBytes: 2 << 20,
	}
}
