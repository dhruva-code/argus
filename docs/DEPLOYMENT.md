# Deployment

## Docker Compose (default)

`docker-compose.yml` at the repo root runs the full stack. See
[INSTALL.md](INSTALL.md). Resource guidance for a single host:

| Service | Memory | Notes |
|---|---|---|
| postgres | 512 MB–1 GB | scale with asset volume |
| redis | 128 MB | `--appendonly yes` for durable queue |
| minio | 256 MB | grows with evidence/reports |
| gateway | 256–512 MB | 1 process; scale horizontally behind a proxy |
| orchestrator | 256 MB + tool overhead | `ORCH_WORKER_CONCURRENCY` controls parallel jobs |
| web | 256 MB | Next.js standalone server |

Add `deploy.resources.limits` blocks in an override file for production.

## Native + systemd

For a no-Docker single host (common on Kali/Parrot pentest boxes): run
`./install.sh --production` directly on the host, then optionally wrap the
three processes (gateway, orchestrator, web) in systemd units for
restart-on-failure and boot-time start — see
[deploy/systemd/README.md](../deploy/systemd/README.md). `run.sh` remains
fully usable with or without the systemd units installed; don't run both
against the same `.env` at once.

## Kubernetes

`deploy/k8s/` contains plain manifests (namespace, config, secret template,
Deployments + Services for gateway/orchestrator/web, and StatefulSets for
postgres/redis/minio). Apply with:

```bash
kubectl apply -k deploy/k8s
```

Key points:

- **Secrets**: `deploy/k8s/secret.example.yaml` is a template — create the real
  `argus-secrets` Secret out of band (sealed-secrets, external-secrets, or
  `kubectl create secret`). Never commit real values.
- **Migrations**: the gateway Deployment runs `alembic upgrade head` in an init
  container so rollouts are ordered.
- **Orchestrator scaling**: increase `replicas`; the Redis queue distributes
  jobs. Each replica needs the tool binaries (init container or a shared image).
- **Storage**: postgres and minio use `PersistentVolumeClaim`s; set a
  `storageClassName` for your cluster.
- **Ingress**: only `web` is exposed. Add your ingress controller's annotations
  to `deploy/k8s/ingress.yaml`.

A Helm chart is planned for M7; the kustomize base is the supported path until
then.

## Observability (M7)

The services emit structured logs today. OpenTelemetry traces, Prometheus
metrics (`scan_duration`, `requests`, `findings`, `worker_utilization`,
`tool_errors`, `429_count`, …) and Grafana dashboards land in M7.
