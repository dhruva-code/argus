// Command orchestrator is the Argus job-execution engine. It consumes jobs from
// the Redis queue, enforces scope and SSRF policy, runs security-tool plugins,
// and streams events back to the gateway.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/argus-platform/orchestrator/internal/config"
	"github.com/argus-platform/orchestrator/internal/engine"
	"github.com/argus-platform/orchestrator/internal/queue"
	"github.com/argus-platform/orchestrator/internal/ssrf"
)

func main() {
	cfg := config.Load()

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	q, err := queue.Connect(cfg.RedisURL)
	if err != nil {
		log.Error("connect redis", "err", err)
		os.Exit(1)
	}
	defer q.Close()

	guard, err := ssrf.NewGuard(cfg.SSRFAllowCIDRs, cfg.SSRFBlockMetadata)
	if err != nil {
		log.Error("ssrf guard", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	eng := engine.New(cfg, q, guard, log)
	if err := eng.Run(ctx); err != nil {
		log.Error("engine stopped", "err", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}
