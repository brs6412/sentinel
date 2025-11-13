#!/bin/bash
# full_demo.sh — run end-to-end LLM demo with logs.
#
# -----------------------------------------------------------------------------
# HOW TO RUN
# -----------------------------------------------------------------------------
# 1. From the repo root, ensure Ollama is running:
#      export OLLAMA_HOST=http://127.0.0.1:11434
#
# 2. Run with default model (llama3.2:3b-instruct-q4_0):
#      ./tools/full_demo.sh
#
# 3. Or specify a custom model:
#      ./tools/full_demo.sh llama3.1:8b
#
# -----------------------------------------------------------------------------
# Notes:
#  - Requires: jq, curl, cmake, ctest, rg
#  - All logs saved to ./runlogs/ with timestamps
#  - Exits nonzero on any failure
#  - Assumes Ollama is already running (does not start it)
# -----------------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

source tools/lib.sh

need jq curl cmake ctest rg

ensure_runlogs
ensure_ollama

MODEL=${1:-llama3.2:3b-instruct-q4_0}

warm_model "$MODEL"
ensure_build || {
    echo "Warning: Build had errors, but continuing with existing binaries" >&2
}

TIMESTAMP=$(ts)

echo "=== Ollama Models ==="
MODELS_OUTPUT=$(curl -fsS "${OLLAMA_HOST:-http://127.0.0.1:11434}/api/tags" | jq -r ".models[].name")
MODELS_STATUS=$?
if [[ $MODELS_STATUS -ne 0 ]]; then
    echo "Error: Failed to fetch Ollama models" >&2
    exit $MODELS_STATUS
fi
echo "$MODELS_OUTPUT" | tee "runlogs/models-${TIMESTAMP}.txt"
MODELS_PIPE_STATUS=(${PIPESTATUS[@]})
if [[ ${MODELS_PIPE_STATUS[0]} -ne 0 ]] || [[ ${MODELS_PIPE_STATUS[1]} -ne 0 ]]; then
    echo "Error: Failed to write models output" >&2
    exit 1
fi

echo ""
echo "=== LLM Smoke Test ==="
LLM_OUTPUT=$(llm_smoke "$MODEL")
LLM_STATUS=$?
if [[ $LLM_STATUS -ne 0 ]]; then
    echo "Error: LLM smoke test failed" >&2
    exit $LLM_STATUS
fi
echo "$LLM_OUTPUT" | jq . 2>/dev/null || echo "$LLM_OUTPUT"
echo "$LLM_OUTPUT" > "runlogs/llm_smoke-${TIMESTAMP}.json" || {
    echo "Error: Failed to write LLM output" >&2
    exit 1
}

echo ""
echo "=== PoE Smoke Test ==="
POE_OUTPUT=$(poe_smoke "$MODEL")
POE_STATUS=$?
if [[ $POE_STATUS -ne 0 ]]; then
    echo "Error: PoE smoke test failed" >&2
    exit $POE_STATUS
fi
echo "$POE_OUTPUT" | jq . 2>/dev/null || echo "$POE_OUTPUT"
echo "$POE_OUTPUT" > "runlogs/poe_smoke-${TIMESTAMP}.json" || {
    echo "Error: Failed to write PoE output" >&2
    exit 1
}
echo "$POE_OUTPUT" > "runlogs/poe_smoke.json" || {
    echo "Error: Failed to write PoE output" >&2
    exit 1
}
POE_SUMMARY=$(echo "$POE_OUTPUT" | jq -r '.summary // empty' 2>/dev/null | head -1)
if [[ -n "$POE_SUMMARY" && "$POE_SUMMARY" != "null" && "$POE_SUMMARY" != "empty" ]]; then
    echo ""
    echo "Summary: $POE_SUMMARY"
fi

echo ""
echo "=== Demo Server Test ==="
if [[ ! -x build/apps/demo_server/demo_server ]]; then
    echo "Error: demo_server not found or not executable" >&2
    exit 1
fi

build/apps/demo_server/demo_server > "runlogs/demo_server-${TIMESTAMP}.log" 2>&1 &
DEMO_PID=$!

sleep 1

if ! curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1 && \
   ! curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1; then
    kill "$DEMO_PID" 2>/dev/null || true
    wait "$DEMO_PID" 2>/dev/null || true
    echo "Error: demo_server did not respond on http://127.0.0.1:8080" >&2
    exit 1
fi

# Keep server running for scanner tests (will be killed at end of script)

echo ""
echo "=== Scanner Test ==="
SCAN_OUTPUT=$(./build/sentinel scan --target http://127.0.0.1:8080 2>&1) || SCAN_STATUS=$?
SCAN_STATUS=${SCAN_STATUS:-$?}
echo "$SCAN_OUTPUT"
SCAN_FINDINGS="0"
SCAN_POINTS="0"
SCAN_BUDGET="0"
if echo "$SCAN_OUTPUT" | grep -qE 'Generated [0-9]+ findings'; then
    SCAN_FINDINGS=$(echo "$SCAN_OUTPUT" | grep -E 'Generated [0-9]+ findings' | sed -E 's/.*Generated ([0-9]+) findings.*/\1/')
fi
if echo "$SCAN_OUTPUT" | grep -qE 'Total risk points: [0-9]+'; then
    SCAN_POINTS=$(echo "$SCAN_OUTPUT" | grep -E 'Total risk points: [0-9]+' | sed -E 's/.*Total risk points: ([0-9]+).*/\1/')
fi
if echo "$SCAN_OUTPUT" | grep -qE 'max: [0-9]+'; then
    SCAN_BUDGET=$(echo "$SCAN_OUTPUT" | grep -E 'max: [0-9]+' | sed -E 's/.*max: ([0-9]+).*/\1/')
fi
echo ""
echo "Summary: Findings: ${SCAN_FINDINGS}; Points: ${SCAN_POINTS}/${SCAN_BUDGET}; ExitCode: ${SCAN_STATUS}"

if [[ $SCAN_STATUS -ne 0 && $SCAN_STATUS -ne 1 && $SCAN_STATUS -ne 2 ]]; then
    echo "Error: Scanner failed with exit code $SCAN_STATUS" >&2
    exit $SCAN_STATUS
fi

echo ""
echo "=== Secure Scanner Test ==="
SECURE_SCAN_OUTPUT=$(./build/sentinel scan --target http://127.0.0.1:8080/secure 2>&1) || SECURE_SCAN_STATUS=$?
SECURE_SCAN_STATUS=${SECURE_SCAN_STATUS:-$?}
echo "$SECURE_SCAN_OUTPUT"
SECURE_SCAN_FINDINGS="0"
SECURE_SCAN_POINTS="0"
SECURE_SCAN_BUDGET="0"
if echo "$SECURE_SCAN_OUTPUT" | grep -qE 'Generated [0-9]+ findings'; then
    SECURE_SCAN_FINDINGS=$(echo "$SECURE_SCAN_OUTPUT" | grep -E 'Generated [0-9]+ findings' | sed -E 's/.*Generated ([0-9]+) findings.*/\1/')
fi
if echo "$SECURE_SCAN_OUTPUT" | grep -qE 'Total risk points: [0-9]+'; then
    SECURE_SCAN_POINTS=$(echo "$SECURE_SCAN_OUTPUT" | grep -E 'Total risk points: [0-9]+' | sed -E 's/.*Total risk points: ([0-9]+).*/\1/')
fi
if echo "$SECURE_SCAN_OUTPUT" | grep -qE 'max: [0-9]+'; then
    SECURE_SCAN_BUDGET=$(echo "$SECURE_SCAN_OUTPUT" | grep -E 'max: [0-9]+' | sed -E 's/.*max: ([0-9]+).*/\1/')
fi
echo ""
echo "Summary: Findings: ${SECURE_SCAN_FINDINGS}; Points: ${SECURE_SCAN_POINTS}/${SECURE_SCAN_BUDGET}; ExitCode: ${SECURE_SCAN_STATUS}"

# Cleanup: kill demo server
kill "$DEMO_PID" 2>/dev/null || true
wait "$DEMO_PID" 2>/dev/null || true

echo ""
echo "Demo completed successfully"
exit $SCAN_STATUS

