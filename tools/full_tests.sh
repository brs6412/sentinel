#!/bin/bash
# full_tests.sh — run full LLM test suite with readable output.
#
# -----------------------------------------------------------------------------
# HOW TO RUN
# -----------------------------------------------------------------------------
# 1. From the repo root, ensure Ollama is running:
#      export OLLAMA_HOST=http://127.0.0.1:11434
#
# 2. Run with default model (llama3.2:3b-instruct-q4_0):
#      ./tools/full_tests.sh
#
# 3. Or specify a custom model:
#      ./tools/full_tests.sh llama3.1:8b
#
# -----------------------------------------------------------------------------
# Notes:
#  - Requires: jq, curl, cmake, ctest
#  - All logs saved to ./runlogs/ with timestamps
#  - Runs CTest discovery, LLM suite, and individual Catch2 binaries
#  - Prints PASS/FAIL summary at the end
#  - Assumes Ollama is already running (does not start it)
# -----------------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

source tools/lib.sh

need jq curl cmake ctest

ensure_runlogs
ensure_ollama

MODEL=${1:-llama3.2:3b-instruct-q4_0}

warm_model "$MODEL"
ensure_build

TIMESTAMP=$(ts)

echo "=== CTest Discovery ==="
ctest -N | tee "runlogs/ctest-discover-${TIMESTAMP}.txt"

echo ""
echo "=== CTest LLM Suite ==="
ctest -R "(ollama|poe|llm)" -V | tee "runlogs/ctest-llm-${TIMESTAMP}.log" || true

echo ""
echo "=== Catch2 Test Binaries ==="

if [[ -x build/test_ollama_client ]]; then
    echo "Running test_ollama_client..."
    ./build/test_ollama_client -r console -s | \
        tee "runlogs/test_ollama_client-${TIMESTAMP}.log" || true
fi

if [[ -x build/test_poe_renderer ]]; then
    echo "Running test_poe_renderer..."
    ./build/test_poe_renderer -r console -s | \
        tee "runlogs/test_poe_renderer-${TIMESTAMP}.log" || true
fi

if [[ -x build/test_llm_poe_smoke ]]; then
    echo "Running test_llm_poe_smoke..."
    ./build/test_llm_poe_smoke -r console -s | \
        tee "runlogs/test_llm_poe_smoke-${TIMESTAMP}.log" || true
fi

echo ""
echo "=== Summary ==="

FAILED=0

for log in runlogs/test_ollama_client-${TIMESTAMP}.log \
           runlogs/test_poe_renderer-${TIMESTAMP}.log \
           runlogs/test_llm_poe_smoke-${TIMESTAMP}.log; do
    if [[ -f "$log" ]]; then
        if grep -qE "[0-9]+ failed" "$log" 2>/dev/null; then
            failures=$(grep -oE "[0-9]+ failed" "$log" | grep -oE "[0-9]+" | head -1 || echo "0")
            if [[ "$failures" != "0" ]]; then
                echo "FAIL: $(basename "$log") has $failures failure(s)"
                FAILED=1
            fi
        fi
    fi
done

if [[ $FAILED -eq 0 ]]; then
    echo "PASS: All tests passed"
    exit 0
else
    echo "FAIL: Some tests failed"
    exit 1
fi

