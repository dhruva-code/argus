#!/usr/bin/env bash
# update.sh — pull the latest changes from git and apply them in place,
# instead of downloading/cloning the package again. Backs up first, stops
# the running services, pulls, rebuilds anything that changed (Python deps,
# Node deps, the orchestrator Go binary), applies pending database
# migrations, then starts everything back up.
#
# Refuses to run over uncommitted local changes (stashes them for you
# instead of discarding anything) and refuses a non-fast-forward pull
# rather than silently rewriting history.
#
# Usage:
#   ./update.sh                  pull + rebuild + migrate + restart
#   ./update.sh --check          report what would change, no changes made
#   ./update.sh --no-restart     update but leave services stopped
#   ./update.sh --non-interactive --force --no-color --quiet --verbose
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=update
# shellcheck source=scripts/lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
log_init update

MODE="update"
DO_RESTART=1

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --no-restart) DO_RESTART=0 ;;
    --non-interactive) ARGUS_NON_INTERACTIVE=1 ;;
    --force) ARGUS_FORCE=1 ;;
    --no-color) ARGUS_NO_COLOR=1 ;;
    --quiet) ARGUS_QUIET=1 ;;
    --verbose) ARGUS_VERBOSE=1 ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) warn "unknown flag: $arg (ignored)" ;;
  esac
done
export ARGUS_NON_INTERACTIVE ARGUS_FORCE ARGUS_NO_COLOR ARGUS_QUIET ARGUS_VERBOSE

# shellcheck source=scripts/lib/os_detection.sh
source "${ARGUS_LIB_DIR}/os_detection.sh"
os_detect
# shellcheck source=scripts/lib/python.sh
source "${ARGUS_LIB_DIR}/python.sh"
# shellcheck source=scripts/lib/node.sh
source "${ARGUS_LIB_DIR}/node.sh"
# shellcheck source=scripts/lib/go.sh
source "${ARGUS_LIB_DIR}/go.sh"
# shellcheck source=scripts/lib/docker.sh
source "${ARGUS_LIB_DIR}/docker.sh"
docker_detect || true
# shellcheck source=scripts/lib/database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=scripts/lib/redis.sh
source "${ARGUS_LIB_DIR}/redis.sh"
# shellcheck source=scripts/lib/services.sh
source "${ARGUS_LIB_DIR}/services.sh"

echo "${C_BOLD}Argus updater${C_RESET} — mode=${MODE}"

cd "$ARGUS_ROOT"

if [[ ! -d .git ]]; then
  die "not a git checkout ($ARGUS_ROOT has no .git) — update.sh only works on a git clone of the repo, not a downloaded tarball"
fi

git fetch --quiet origin || die "git fetch failed — check network connectivity to the remote"

LOCAL_REV="$(git rev-parse HEAD)"
REMOTE_REV="$(git rev-parse '@{u}' 2>/dev/null || echo "")"
if [[ -z "$REMOTE_REV" ]]; then
  die "current branch has no upstream tracking branch configured — nothing to pull from"
fi

if [[ "$LOCAL_REV" == "$REMOTE_REV" ]]; then
  ok "already up to date ($LOCAL_REV)"
  exit 0
fi

BEHIND="$(git rev-list --count "HEAD..@{u}")"
AHEAD="$(git rev-list --count '@{u}..HEAD')"
info "local is ${AHEAD} commit(s) ahead, ${BEHIND} commit(s) behind origin"
git log --oneline "HEAD..@{u}" | sed 's/^/    /'

if [[ "$MODE" == "check" ]]; then
  info "run without --check to apply this update"
  exit 0
fi

DIRTY="$(git status --porcelain)"
STASHED=0
if [[ -n "$DIRTY" ]]; then
  warn "uncommitted local changes present — stashing them (recoverable with: git stash pop)"
  git stash push -u -m "update.sh auto-stash $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  STASHED=1
fi

if ! git merge-base --is-ancestor "$LOCAL_REV" "$REMOTE_REV" 2>/dev/null; then
  [[ "$STASHED" == "1" ]] && git stash pop || true
  die "local branch has diverged from origin (${AHEAD} commit(s) not on origin) — a plain pull would need a merge/rebase; resolve that yourself first (git status), then re-run"
fi

step "Backing up before update"
"${SCRIPT_DIR}/scripts/backup.sh" || warn "backup step failed — continuing anyway"

WAS_RUNNING=0
if service_is_running gateway || service_is_running orchestrator || service_is_running web; then
  WAS_RUNNING=1
  step "Stopping services for the update"
  services_stop_all
fi

step "Pulling latest changes"
git pull --ff-only origin "$(git rev-parse --abbrev-ref HEAD)" || {
  [[ "$STASHED" == "1" ]] && git stash pop || true
  die "git pull --ff-only failed"
}

if [[ "$STASHED" == "1" ]]; then
  info "restoring your stashed local changes…"
  if ! git stash pop; then
    warn "stash pop had conflicts — resolve manually (git status / git stash list); your changes are safe in the stash until then"
  fi
fi

CHANGED_FILES="$(git diff --name-only "$LOCAL_REV" HEAD)"

step "Applying updates"

if grep -q '^apis/gateway/requirements' <<<"$CHANGED_FILES" || grep -q '^apis/gateway/pyproject.toml$' <<<"$CHANGED_FILES"; then
  info "Python dependencies changed — reinstalling…"
  python_setup
else
  verbose "no Python dependency changes"
fi

if grep -q '^web/package.*\.json$' <<<"$CHANGED_FILES"; then
  info "Node dependencies changed — reinstalling…"
  node_setup
else
  verbose "no Node dependency changes"
fi

if grep -qE '^orchestrator/' <<<"$CHANGED_FILES"; then
  info "orchestrator source changed — rebuilding…"
  go_setup || true
  ( cd "$ARGUS_ORCH_DIR" && go build -o bin/orchestrator ./cmd/orchestrator ) ||
    die "failed to rebuild the orchestrator binary"
  ok "orchestrator rebuilt"
else
  verbose "no orchestrator source changes"
fi

if grep -q '^web/' <<<"$CHANGED_FILES"; then
  info "web source changed — rebuilding (next build)…"
  ( cd "$ARGUS_WEB_DIR" && npm run build ) || warn "web build failed — check ${ARGUS_LOG_DIR}/update.log"
fi

if grep -q '^apis/gateway/alembic/' <<<"$CHANGED_FILES"; then
  info "new database migration(s) detected"
fi
db_start || die "postgres could not be started — see the diagnostic above"
db_migrate || die "database migrations failed — see ${ARGUS_LOG_DIR}/update.log"

ok "update applied: $(git rev-parse --short "$LOCAL_REV") -> $(git rev-parse --short HEAD)"

if [[ "$DO_RESTART" == "1" && "$WAS_RUNNING" == "1" ]]; then
  step "Restarting services"
  redis_start || die "redis could not be started — see the diagnostic above"
  services_start_all
  sleep 2
  services_status
elif [[ "$DO_RESTART" == "0" ]]; then
  info "--no-restart passed — services left stopped; start with ./run.sh"
else
  info "services were not running before the update — start with ./run.sh"
fi
