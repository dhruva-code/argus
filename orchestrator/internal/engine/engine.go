// Package engine is the orchestrator worker loop: claim jobs from the queue,
// run them under a cancellable context, stream events back, heartbeat, and
// honor control messages (pause / cancel / emergency stop-all).
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/argus-platform/orchestrator/internal/config"
	"github.com/argus-platform/orchestrator/internal/jobs"
	"github.com/argus-platform/orchestrator/internal/plugin"
	"github.com/argus-platform/orchestrator/internal/queue"
	"github.com/argus-platform/orchestrator/internal/ssrf"
	"github.com/argus-platform/orchestrator/internal/tools"
)

type Engine struct {
	cfg    config.Config
	q      *queue.Queue
	reg    *tools.Registry
	runner plugin.Runner
	guard  *ssrf.Guard
	worker string
	log    *slog.Logger

	mu       sync.Mutex
	inflight map[string]context.CancelFunc
	stopAll  bool
}

func New(cfg config.Config, q *queue.Queue, guard *ssrf.Guard, log *slog.Logger) *Engine {
	return &Engine{
		cfg:      cfg,
		q:        q,
		reg:      tools.BuiltIn(),
		runner:   plugin.ExecRunner{BinDir: cfg.ToolsBinDir},
		guard:    guard,
		worker:   fmt.Sprintf("orch-%d", time.Now().Unix()),
		log:      log,
		inflight: map[string]context.CancelFunc{},
	}
}

// Run blocks until ctx is cancelled. It starts the control listener, a stale-job
// recovery sweep, and the worker pool.
func (e *Engine) Run(ctx context.Context) error {
	ctrl, err := e.q.SubscribeControl(ctx)
	if err != nil {
		return fmt.Errorf("subscribe control: %w", err)
	}
	go e.handleControl(ctx, ctrl)

	if n, err := e.q.RecoverStale(ctx); err != nil {
		e.log.Warn("stale recovery failed", "err", err)
	} else if n > 0 {
		e.log.Info("recovered stale jobs", "count", n)
	}

	go e.livenessBeacon(ctx)

	var wg sync.WaitGroup
	for i := 0; i < e.cfg.WorkerConcurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.workerLoop(ctx, id)
		}(i)
	}
	e.log.Info("orchestrator running", "workers", e.cfg.WorkerConcurrency, "worker_id", e.worker)
	wg.Wait()
	return nil
}

func (e *Engine) workerLoop(ctx context.Context, id int) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, err := e.q.Claim(ctx, 2*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.log.Warn("claim failed", "worker", id, "err", err)
			time.Sleep(time.Second)
			continue
		}
		if job == nil {
			continue
		}
		e.runJob(ctx, job)
	}
}

func (e *Engine) runJob(parent context.Context, job *jobs.Job) {
	e.mu.Lock()
	if e.stopAll {
		e.mu.Unlock()
		_ = e.q.Requeue(parent, job.ID)
		return
	}
	jctx, cancel := context.WithCancel(parent)
	e.inflight[job.ID] = cancel
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		delete(e.inflight, job.ID)
		e.mu.Unlock()
		cancel()
		_ = e.q.Ack(context.Background(), job.ID)
	}()

	e.emit(job, queue.Event{Type: "status", Status: jobs.StatusRunning, Level: "INFO",
		Message: fmt.Sprintf("worker %s started job %s (%s)", e.worker, job.ID, job.Type)})

	hbCtx, hbStop := context.WithCancel(jctx)
	defer hbStop()
	go e.heartbeat(hbCtx, job.ID)

	h, ok := handlers[job.Type]
	if !ok {
		e.emit(job, queue.Event{Type: "status", Status: jobs.StatusFailed, Level: "ERROR",
			Message: "no handler for job type " + string(job.Type)})
		return
	}

	rc := &RunContext{Job: job, Engine: e, Ctx: jctx}
	status, err := h(rc)
	if err != nil {
		e.emit(job, queue.Event{Type: "error", Level: "ERROR", Message: err.Error()})
	}
	if jctx.Err() != nil && status != jobs.StatusCancelled {
		status = jobs.StatusCancelled
	}
	e.emit(job, queue.Event{Type: "status", Status: status, Level: "INFO",
		Message: fmt.Sprintf("job %s finished: %s", job.ID, status)})
}

func (e *Engine) heartbeat(ctx context.Context, jobID string) {
	ttl := time.Duration(e.cfg.HeartbeatSeconds*3) * time.Second
	t := time.NewTicker(time.Duration(e.cfg.HeartbeatSeconds) * time.Second)
	defer t.Stop()
	_ = e.q.Heartbeat(ctx, jobID, e.worker, ttl)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = e.q.Heartbeat(ctx, jobID, e.worker, ttl)
		}
	}
}

// livenessBeacon refreshes argus:orch:alive so the gateway's System Health
// screen can tell an operator whether any worker is running.
func (e *Engine) livenessBeacon(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	_ = e.q.SetAlive(ctx, e.worker, 30*time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = e.q.SetAlive(ctx, e.worker, 30*time.Second)
		}
	}
}

func (e *Engine) handleControl(ctx context.Context, ch <-chan queue.ControlMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			switch msg.Action {
			case "stop_all":
				e.log.Warn("EMERGENCY STOP ALL received")
				e.mu.Lock()
				e.stopAll = true
				for id, c := range e.inflight {
					e.log.Warn("cancelling job", "id", id)
					c()
				}
				e.mu.Unlock()
			case "resume_all":
				e.mu.Lock()
				e.stopAll = false
				e.mu.Unlock()
				e.log.Info("stop-all cleared; accepting jobs again")
			case "stop", "pause":
				e.mu.Lock()
				if c, ok := e.inflight[msg.JobID]; ok {
					c()
				}
				e.mu.Unlock()
			}
		}
	}
}

func (e *Engine) emit(job *jobs.Job, ev queue.Event) {
	ev.JobID = job.ID
	ev.ProjectID = job.ProjectID
	if err := e.q.Publish(context.Background(), ev); err != nil {
		e.log.Warn("publish event failed", "err", err)
	}
}
