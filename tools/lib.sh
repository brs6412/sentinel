#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

ts() {
    date -u +"%Y%m%d-%H%M%S"
}

need() {
    local cmd
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: required command '$cmd' not found" >&2
            exit 1
        fi
    done
}

ensure_runlogs() {
    mkdir -p ./runlogs
}

ensure_build() {
    rm -rf build
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j
}

ensure_ollama() {
    export OLLAMA_HOST=${OLLAMA_HOST:-http://127.0.0.1:11434}
    if ! curl -fsS "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
        echo "Ollama not reachable on ${OLLAMA_HOST}" >&2
        exit 2
    fi
}

warm_model() {
    local tag=${1:-llama3.2:3b-instruct-q4_0}
    export OLLAMA_HOST=${OLLAMA_HOST:-http://127.0.0.1:11434}
    ollama pull "$tag" || true
    curl -fsS "${OLLAMA_HOST}/api/generate" \
        -H 'Content-Type: application/json' \
        -d '{"model":"'"$tag"'","prompt":"ping","stream":false}' >/dev/null 2>&1 || true
}

llm_smoke() {
    local tag=${1:-llama3.2:3b-instruct-q4_0}
    ./build/apps/llm/sentinel_llm \
        --model "$tag" \
        --prompt "Say 'Sentinel LLM OK' and nothing else." \
        --json
}

poe_smoke() {
    local tag=${1:-llama3.2:3b-instruct-q4_0}
    local prompt_file="apps/demo_server/fixtures/poe_prompt.sample.json"
    if [[ ! -f "$prompt_file" ]]; then
        echo "Error: $prompt_file not found" >&2
        return 1
    fi
    local wrapped_prompt
    wrapped_prompt=$(jq -c '{instruction: "You are Sentinel PoE. Read the field '\''finding'\'' (JSON). Output ONLY a single JSON object with exactly these keys: summary, why, fix, test, tags: { cwe, owasp }. No markdown, no prose outside JSON, no code fences.", finding: .}' "$prompt_file")
    
    local raw_response
    raw_response=$(./build/apps/llm/sentinel_llm \
        --model "$tag" \
        --prompt "$wrapped_prompt" \
        --json 2>/dev/null)
    if [[ -z "$raw_response" ]]; then
        echo "Error: No response from LLM" >&2
        return 1
    fi
    
    local response_text
    response_text=$(echo "$raw_response" | jq -r '.response // .' 2>/dev/null || echo "$raw_response")
    
    local json_start json_end
    json_start=$(echo "$response_text" | grep -bo '{' | head -1 | cut -d: -f1)
    json_end=$(echo "$response_text" | grep -bo '}' | tail -1 | cut -d: -f1)
    if [[ -n "$json_start" && -n "$json_end" && "$json_end" -gt "$json_start" ]]; then
        response_text=$(echo "$response_text" | cut -c$((json_start+1))-$((json_end+1)))
    fi
    
    local filtered
    filtered=$(echo "$response_text" | jq -c '{summary, why, fix, test, tags: {cwe: (.tags.cwe // "" | tostring), owasp: (.tags.owasp // "" | tostring)}}' 2>/dev/null)
    
    if [[ -z "$filtered" || "$filtered" == "null" ]]; then
        wrapped_prompt=$(jq -c '{instruction: "If output is not valid JSON, you will be scored 0; try again. Emit JSON now. You are Sentinel PoE. Read the field '\''finding'\'' (JSON). Output ONLY a single JSON object with exactly these keys: summary, why, fix, test, tags: { cwe, owasp }. No markdown, no prose outside JSON, no code fences.", finding: .}' "$prompt_file")
        raw_response=$(./build/apps/llm/sentinel_llm \
            --model "$tag" \
            --prompt "$wrapped_prompt" \
            --json 2>/dev/null)
        if [[ -z "$raw_response" ]]; then
            echo "Error: No response from LLM on retry" >&2
            return 1
        fi
        response_text=$(echo "$raw_response" | jq -r '.response // .' 2>/dev/null || echo "$raw_response")
        json_start=$(echo "$response_text" | grep -bo '{' | head -1 | cut -d: -f1)
        json_end=$(echo "$response_text" | grep -bo '}' | tail -1 | cut -d: -f1)
        if [[ -n "$json_start" && -n "$json_end" && "$json_end" -gt "$json_start" ]]; then
            response_text=$(echo "$response_text" | cut -c$((json_start+1))-$((json_end+1)))
        fi
        filtered=$(echo "$response_text" | jq -c '{summary, why, fix, test, tags: {cwe: (.tags.cwe // "" | tostring), owasp: (.tags.owasp // "" | tostring)}}' 2>/dev/null)
    fi
    
    if [[ -n "$filtered" && "$filtered" != "null" ]]; then
        echo "$filtered" | jq .
    else
        echo "Error: Failed to extract valid JSON from LLM response" >&2
        return 1
    fi
}

