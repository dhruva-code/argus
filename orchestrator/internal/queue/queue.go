// Package queue is the Redis-backed durable job queue, event bus, and control
// channel that connect the gateway and the orchestrator.
//
// Keys:
//
//	argus:jobs:queued       LIST  — job IDs awaiting a worker (FIFO)
//	argus:jobs:processing   LIST  — job IDs claimed by a worker (crash recovery)
//	argus:job:<id>          STRING — the JSON job payload
//	argus:job:<id>:hb       STRING — worker heartbeat, short TTL
//	argus:job:<id>:ckpt     STRING — last checkpoint, for resume
//	argus:events            PUBSUB — status + log events consumed by the gateway
//	argus:control           PUBSUB — stop_all / stop:<id> / pause:<id> / resume:<id>
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/argus-platform/orchestrator/internal/jobs"
	"github.com/redis/go-redis/v9"
)

const (
	KeyQueued     = "argus:jobs:queued"
	KeyProcessing = "argus:jobs:processing"
	ChanEvents    = "argus:events"
	ChanControl   = "argus:control"
)

type Queue struct {
	rdb *redis.Client
}

func Connect(url string) (*Queue, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	rdb := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Queue{rdb: rdb}, nil
}

func (q *Queue) Close() error { return q.rdb.Close() }

// Claim blocks until a job ID is available, atomically moving it from the
// queued list to the processing list, then loads and returns the payload.
func (q *Queue) Claim(ctx context.Context, timeout time.Duration) (*jobs.Job, error) {
	id, err := q.rdb.BLMove(ctx, KeyQueued, KeyProcessing, "LEFT", "RIGHT", timeout).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil // timeout, no job
	}
	if err != nil {
		return nil, err
	}
	raw, err := q.rdb.Get(ctx, "argus:job:"+id).Bytes()
	if err != nil {
		return nil, fmt.Errorf("load job %s: %w", id, err)
	}
	var j jobs.Job
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("decode job %s: %w", id, err)
	}
	return &j, nil
}

// Ack removes a finished job ID from the processing list.
func (q *Queue) Ack(ctx context.Context, id string) error {
	return q.rdb.LRem(ctx, KeyProcessing, 1, id).Err()
}

// Requeue moves a job ID back to the head of the queued list (used when a
// worker is shutting down mid-job).
func (q *Queue) Requeue(ctx context.Context, id string) error {
	pipe := q.rdb.TxPipeline()
	pipe.LRem(ctx, KeyProcessing, 1, id)
	pipe.LPush(ctx, KeyQueued, id)
	_, err := pipe.Exec(ctx)
	return err
}

// Heartbeat writes a short-TTL key proving the worker still owns the job.
func (q *Queue) Heartbeat(ctx context.Context, id, worker string, ttl time.Duration) error {
	return q.rdb.Set(ctx, "argus:job:"+id+":hb", worker, ttl).Err()
}

// SetAlive refreshes the orchestrator liveness key read by the gateway's
// System Health screen.
func (q *Queue) SetAlive(ctx context.Context, worker string, ttl time.Duration) error {
	return q.rdb.Set(ctx, "argus:orch:alive", worker, ttl).Err()
}

// SaveCheckpoint persists resumable progress for a job.
func (q *Queue) SaveCheckpoint(ctx context.Context, id string, ckpt map[string]any) error {
	b, err := json.Marshal(ckpt)
	if err != nil {
		return err
	}
	return q.rdb.Set(ctx, "argus:job:"+id+":ckpt", b, 24*time.Hour).Err()
}

// Event is a status or log message the gateway persists and forwards to SSE
// clients.
type Event struct {
	JobID     string         `json:"job_id"`
	ProjectID string         `json:"project_id"`
	Type      string         `json:"type"` // status | log | result | error | heartbeat
	Status    jobs.Status    `json:"status,omitempty"`
	Level     string         `json:"level,omitempty"` // INFO WARNING ERROR DEBUG TOOL RESULT
	Message   string         `json:"message,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	At        time.Time      `json:"at"`
}

func (q *Queue) Publish(ctx context.Context, e Event) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return q.rdb.Publish(ctx, ChanEvents, b).Err()
}

// ── control channel ─────────────────────────────────────────────────────────

type ControlMsg struct {
	Action string `json:"action"` // stop_all | stop | pause | resume
	JobID  string `json:"job_id,omitempty"`
}

// SubscribeControl returns a channel of decoded control messages.
func (q *Queue) SubscribeControl(ctx context.Context) (<-chan ControlMsg, error) {
	sub := q.rdb.Subscribe(ctx, ChanControl)
	if _, err := sub.Receive(ctx); err != nil {
		return nil, err
	}
	out := make(chan ControlMsg, 16)
	go func() {
		defer close(out)
		ch := sub.Channel()
		for {
			select {
			case <-ctx.Done():
				_ = sub.Close()
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				var cm ControlMsg
				if json.Unmarshal([]byte(msg.Payload), &cm) == nil {
					out <- cm
				}
			}
		}
	}()
	return out, nil
}

// RecoverStale moves job IDs that were left in the processing list (worker
// crash) back to the queue if their heartbeat has expired.
func (q *Queue) RecoverStale(ctx context.Context) (int, error) {
	ids, err := q.rdb.LRange(ctx, KeyProcessing, 0, -1).Result()
	if err != nil {
		return 0, err
	}
	recovered := 0
	for _, id := range ids {
		exists, err := q.rdb.Exists(ctx, "argus:job:"+id+":hb").Result()
		if err != nil {
			return recovered, err
		}
		if exists == 0 {
			if err := q.Requeue(ctx, id); err != nil {
				return recovered, err
			}
			recovered++
		}
	}
	return recovered, nil
}
