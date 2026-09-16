#!/usr/bin/env bash
# scripts/lib/ollama.sh — local AI (Ollama + Qwen) detection, install,
# start, model provisioning, and health checks.
#
# Fully optional/best-effort by design: Argus's core recon/scanning
# functionality never depends on this. A missing or broken Ollama just
# means AI-assisted analysis falls back to the deterministic heuristic
# (see apis/gateway/app/services/ai.py) — never a blocker for the rest of
# the app. Every function here warns and returns non-zero on failure; none
# of them ever `die`.
# shellcheck shell=bash

if [[ -n "${ARGUS_OLLAMA_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_OLLAMA_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

OLLAMA_DEFAULT_BASE_URL="http://localhost:11434"

ollama_env() {
  [[ -f "$ARGUS_ENV_FILE" ]] || { echo ""; return 0; }
  grep -E "^${1}=" "$ARGUS_ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true
}

ollama_base_url() {
  local url; url="$(ollama_env ARGUS_OLLAMA_BASE_URL)"
  echo "${url:-$OLLAMA_DEFAULT_BASE_URL}"
}

ollama_api_reachable() {
  curl -fsS --max-time 5 "$(ollama_base_url)/api/tags" >/dev/null 2>&1
}

# ollama_pick_model — chooses a Qwen 2.5 model size with a realistic chance
# of actually running on this host's RAM, instead of a single hardcoded
# default. A 14B Q4_K_M model needs ~9GB+ resident just for weights —
# confirmed empirically (this project's own test notes) to trigger the
# Linux OOM killer on a 4-core/7.2GB host. Conservative bands, leaving
# headroom for the rest of the stack (Postgres/Redis/gateway/orchestrator)
# running on the same box. Override with ARGUS_OLLAMA_MODEL in .env if you
# know better for your hardware.
ollama_pick_model() {
  local mem_gb="${1:-}"
  if [[ -z "$mem_gb" ]]; then
    mem_gb="$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1024 / 1024 ))"
  fi
  if [[ "$mem_gb" -ge 24 ]]; then echo "qwen2.5:14b"
  elif [[ "$mem_gb" -ge 12 ]]; then echo "qwen2.5:7b"
  elif [[ "$mem_gb" -ge 6 ]]; then echo "qwen2.5:3b"
  else echo "qwen2.5:1.5b"
  fi
}

ollama_configured_model() {
  local m; m="$(ollama_env ARGUS_OLLAMA_MODEL)"
  echo "${m:-$(ollama_pick_model)}"
}

ollama_installed_version() {
  has_cmd ollama || return 1
  ollama --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

ollama_model_present() {
  local model="$1" names
  names="$(curl -fsS --max-time 5 "$(ollama_base_url)/api/tags" 2>/dev/null | jq -r '.models[].name' 2>/dev/null || true)"
  [[ -z "$names" ]] && return 1
  # Exact name:tag match ONLY — different sizes of the same family (3b vs
  # 14b) are different models with very different resource footprints, so
  # a fuzzy family-prefix match would defeat ollama_pick_model's whole
  # point of choosing a size that actually fits this host (confirmed live:
  # a host with only qwen2.5:14b pulled was being reported as satisfying a
  # qwen2.5:3b request, which then 404'd on the real inference call).
  grep -qxF "$model" <<<"$names"
}

# ollama_install — the official upstream install script (root-agnostic: it
# self-elevates via sudo internally when not already root, same as every
# other install-script-based tool this project installs — see tools.sh).
ollama_install() {
  step "Installing Ollama"
  if has_cmd ollama; then
    ok "ollama already installed ($(ollama_installed_version || echo '?'))"
    return 0
  fi
  info "installing via the official Ollama install script…"
  if curl -fsSL https://ollama.com/install.sh | run_cmd "ollama install script" -- sh; then
    ok "ollama installed"
  else
    warn "ollama install script failed — AI analysis will use the heuristic fallback (see docs/AI.md to install manually)"
    return 1
  fi
}

ollama_start() {
  step "Starting Ollama"
  if ollama_api_reachable; then
    ok "ollama already reachable at $(ollama_base_url)"
    return 0
  fi
  if [[ "$OS_HAS_SYSTEMD" == "1" ]] && systemctl list-unit-files 2>/dev/null | grep -q '^ollama\.service'; then
    info "starting ollama via systemd…"
    sudo_run systemctl enable --now ollama >/dev/null 2>&1 || sudo_run systemctl start ollama
  elif has_cmd ollama; then
    info "starting ollama serve in the background…"
    nohup ollama serve >"${ARGUS_LOG_DIR}/ollama.log" 2>&1 &
    disown 2>/dev/null || true
  else
    warn "ollama is not installed — nothing to start"
    return 1
  fi
  local i
  for ((i = 0; i < 30; i++)); do
    ollama_api_reachable && { ok "ollama service reachable at $(ollama_base_url)"; return 0; }
    sleep 1
  done
  warn "ollama did not become reachable within 30s — see ${ARGUS_LOG_DIR}/ollama.log"
  return 1
}

# ollama_pull_model — idempotent; `ollama pull` on an already-present model
# is a fast no-op (checksums, no re-download).
ollama_pull_model() {
  local model="$1"
  if ollama_model_present "$model"; then
    ok "model '$model' already present"
    return 0
  fi
  info "pulling model '$model' (this can take a while — several GB over the network)…"
  if has_cmd ollama; then
    run_cmd "ollama pull $model" -- ollama pull "$model"
  else
    curl -fsS --max-time 1800 -X POST "$(ollama_base_url)/api/pull" \
      -H 'content-type: application/json' \
      -d "$(jq -n --arg m "$model" '{name:$m,stream:false}')" >/dev/null
  fi
  if ollama_model_present "$model"; then
    ok "model '$model' pulled"
  else
    warn "model '$model' pull did not complete — AI analysis will use the heuristic fallback"
    return 1
  fi
}

# ollama_inference_test — a real, short chat completion, not just an /api/tags
# ping. A generous timeout: cold-loading a multi-GB model off disk on
# CPU-only hardware can itself take a minute or more before generation
# even starts — this is a one-time install-time cost, not a runtime one
# (Ollama keeps the model warm in memory for a few minutes after use).
ollama_inference_test() {
  local model="$1"
  step "Ollama inference test ($model)"
  local resp
  resp="$(curl -fsS --max-time 120 -X POST "$(ollama_base_url)/api/chat" \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg m "$model" '{model:$m,messages:[{role:"user",content:"Reply with the single word: ok"}],stream:false,options:{num_predict:8}}')" \
    2>/dev/null || true)"
  if [[ -n "$resp" ]] && jq -e '.message.content' >/dev/null 2>&1 <<<"$resp"; then
    ok "inference test passed"
    return 0
  fi
  warn "inference test failed — the service responded but a real chat call did not return a completion (timeout, OOM-killed, or under-resourced host for this model size — see docs/AI.md; AI analysis will use the heuristic fallback)"
  return 1
}

# ollama_check — the doctor.sh / install.sh --check pass. Never treats "the
# binary/process exists" as healthy on its own (§15) — a real API call and
# a real inference call are both required to report [PASS].
ollama_check() {
  section "OLLAMA / QWEN"
  if ! has_cmd ollama; then
    warn "ollama not installed (optional — AI analysis uses the deterministic heuristic fallback)"
    return 0
  fi
  local v; v="$(ollama_installed_version || true)"
  [[ -n "$v" ]] && ok "ollama $v" || warn "ollama installed but version could not be determined"

  if ! ollama_api_reachable; then
    fail "ollama service not reachable at $(ollama_base_url) (installed but not running — try: ollama serve, or ./repair.sh)"
    return 1
  fi
  ok "ollama service reachable at $(ollama_base_url)"

  local model; model="$(ollama_configured_model)"
  if ! ollama_model_present "$model"; then
    fail "configured model '$model' is not pulled — run: ollama pull $model (or ./repair.sh)"
    return 1
  fi
  ok "model '$model' available"

  ollama_inference_test "$model" || return 1
  return 0
}

# ollama_setup — the install.sh entry point: install if missing, start,
# pick+persist a model appropriate for this host's RAM, pull it, verify
# with a real inference call, and write the resolved config into .env so
# the gateway's AI service picks it up automatically (no manual Settings
# step required for the env-var fallback path — see
# apis/gateway/app/services/ai.py:resolve_config). Best-effort throughout:
# any failure warns and returns non-zero, never `die`s — install.sh must
# keep going without Ollama.
ollama_setup() {
  step "Ollama / Qwen (local AI — optional)"
  ollama_install || return 1
  ollama_start || return 1

  local model; model="$(ollama_env ARGUS_OLLAMA_MODEL)"
  if [[ -z "$model" ]]; then
    model="$(ollama_pick_model)"
    info "selected model '$model' based on detected RAM (override with ARGUS_OLLAMA_MODEL in .env)"
    if grep -q '^ARGUS_OLLAMA_MODEL=' "$ARGUS_ENV_FILE" 2>/dev/null; then
      sed -i "s|^ARGUS_OLLAMA_MODEL=.*|ARGUS_OLLAMA_MODEL=${model}|" "$ARGUS_ENV_FILE"
    else
      { echo ""; echo "# Local AI (Ollama) — selected automatically by install.sh based on"; \
        echo "# detected RAM; override if you know better for your hardware."; \
        echo "ARGUS_OLLAMA_BASE_URL=$(ollama_base_url)"; \
        echo "ARGUS_OLLAMA_MODEL=${model}"; } >>"$ARGUS_ENV_FILE"
    fi
  fi

  ollama_pull_model "$model" || return 1
  ollama_inference_test "$model" || return 1
  ok "Ollama/Qwen ready — model '$model'"
}

ollama_repair() {
  step "Repairing Ollama"
  if ! has_cmd ollama; then
    verbose "ollama not installed — nothing to repair (install.sh installs it if desired)"
    return 0
  fi
  ollama_api_reachable || { fix "ollama unreachable — attempting to start it"; ollama_start; }
  local model; model="$(ollama_configured_model)"
  ollama_model_present "$model" || { fix "model '$model' missing — pulling it"; ollama_pull_model "$model"; }
}
