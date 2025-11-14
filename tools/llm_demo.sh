#!/usr/bin/env bash
set -euo pipefail

# === Config you can tweak ===
MODEL_TAG="${MODEL_TAG:-llama3.2:3b-instruct-q4_0}"
PROMPT1=${PROMPT1:-"Say 'Sentinel LLM OK' and nothing else."}
PROMPT2=${PROMPT2:-'{"finding":"reflected_xss","url":"/post?id=2"}'}

# Always prefer 127.0.0.1 to avoid IPv6/::1 weirdness
export OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"

# Sentinel client (path built by your CMake)
SENTINEL_LLM_BIN="${SENTINEL_LLM_BIN:-./build/apps/llm/sentinel_llm}"

# === Helpers ===
die() { echo "ERROR: $*" >&2; exit 1; }

wait_for_ollama() {
  echo "Waiting for Ollama at $OLLAMA_HOST ..."
  for i in {1..60}; do
    if curl -sS -m 1 "${OLLAMA_HOST}/" >/dev/null; then
      echo "Ollama is up."
      return 0
    fi
    sleep 1
  done
  die "Ollama never became reachable at $OLLAMA_HOST"
}

ensure_model_present() {
  echo "Ensuring model present: $MODEL_TAG"
  # Pull will return quickly if already present
  curl -sS "${OLLAMA_HOST}/api/pull" \
    -d "{\"name\":\"${MODEL_TAG}\"}" >/dev/null || true
  # Verify tag exists
  if ! curl -sS "${OLLAMA_HOST}/api/tags" | grep -q "\"name\":\"${MODEL_TAG}\""; then
    echo "Available models:"
    curl -sS "${OLLAMA_HOST}/api/tags"
    die "Model tag '${MODEL_TAG}' not found on this Ollama instance"
  fi
}

warm_model_once() {
  echo "Warming model (first generate may cold-load weights) ..."
  # Use stream:false so curl waits for a full response; give a generous timeout
  curl -sS --max-time 120 "${OLLAMA_HOST}/api/generate" \
    -d "{\"model\":\"${MODEL_TAG}\",\"prompt\":\"ping\",\"stream\":false}" \
    | jq -r '.response' || die "Warmup failed"
  echo "Warmup done."
}

run_sentinel() {
  echo
  echo "Running sentinel_llm (PROMPT1) ..."
  "${SENTINEL_LLM_BIN}" \
    --model "${MODEL_TAG}" \
    --prompt "${PROMPT1}" \
    --json | jq .

  echo
  echo "Running sentinel_llm (PROMPT2) ..."
  "${SENTINEL_LLM_BIN}" \
    --model "${MODEL_TAG}" \
    --prompt "${PROMPT2}" \
    --json | jq .
}

# === Flow ===
command -v jq >/dev/null || die "jq is required"
[ -x "${SENTINEL_LLM_BIN}" ] || die "Binary not found: ${SENTINEL_LLM_BIN}"

wait_for_ollama
ensure_model_present
warm_model_once
run_sentinel

echo
echo "All good ✅"
