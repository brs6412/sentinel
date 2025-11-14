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
    wrapped_prompt=$(jq -c '{instruction: "You are Sentinel PoE. Read the field '\''finding'\'' (JSON). Output ONLY a single JSON object with exactly these keys: summary, why, fix, test, tags: { cwe, owasp }. No markdown, no prose outside JSON, no code fences. The '\''test'\'' field MUST be either: (1) a short checklist of concrete steps to verify the fix (for example, bullet-like text starting with '\''-'\'' or '\''1.'\''), OR (2) a tiny, copy/pasteable code snippet, such as a curl command or a minimal unit test skeleton. Make it specific to this vulnerability. Avoid vague statements like '\''verify it works'\'' – show exactly what to run or check. If emitting code, use something simple like curl or Python/pytest-style function. Checklist format is fine (e.g., '\''- send request without header; - send request with header; compare results'\''). The test field may contain newlines for multiple checklist lines or code.", finding: .}' "$prompt_file")
    
    local raw_response
    raw_response=$(./build/apps/llm/sentinel_llm \
        --model "$tag" \
        --prompt "$wrapped_prompt" \
        --json \
        --timeout-ms 30000 \
        2>&1)
    local llm_status=$?
    if [[ $llm_status -ne 0 ]]; then
        echo "Error: LLM call failed with status $llm_status" >&2
        echo "Response: $raw_response" >&2
        return 1
    fi
    if [[ -z "$raw_response" ]]; then
        echo "Error: No response from LLM" >&2
        return 1
    fi
    
    # Extract and parse the JSON response using Python
    # The response is wrapped in {"response": "..."} where the inner string is JSON
    # Use regex extraction to handle malformed JSON with literal newlines
    local filtered
    filtered=$(echo "$raw_response" | python3 -c "
import sys, json, re
try:
    outer = json.load(sys.stdin)
    response_str = outer.get('response', '{}')
    # Extract fields using regex to handle malformed JSON
    summary_match = re.search(r'\"summary\"\s*:\s*\"([^\"]*)\"', response_str)
    why_match = re.search(r'\"why\"\s*:\s*\"([^\"]*)\"', response_str)
    fix_match = re.search(r'\"fix\"\s*:\s*\"([^\"]*)\"', response_str)
    # Test field may contain escaped newlines, so use DOTALL and handle escapes
    test_match = re.search(r'\"test\"\s*:\s*\"((?:[^\"\\\\]|\\\\.)*)\"', response_str, re.DOTALL)
    cwe_match = re.search(r'\"cwe\"\s*:\s*\"([^\"]*)\"', response_str)
    owasp_match = re.search(r'\"owasp\"\s*:\s*\"([^\"]*)\"', response_str)
    # Extract tags object if present
    tags_match = re.search(r'\"tags\"\s*:\s*\{[^}]*\"cwe\"\s*:\s*\"([^\"]*)\"[^}]*\"owasp\"\s*:\s*\"([^\"]*)\"', response_str)
    if tags_match:
        cwe_val = tags_match.group(1)
        owasp_val = tags_match.group(2)
    else:
        cwe_val = cwe_match.group(1) if cwe_match else ''
        owasp_val = owasp_match.group(1) if owasp_match else ''
    test_val = test_match.group(1) if test_match else ''
    # Unescape newlines in test field
    test_val = test_val.replace('\\\\n', '\n').replace('\\\\r', '\r').replace('\\\\t', '\t')
    result = {
        'summary': summary_match.group(1) if summary_match else '',
        'why': why_match.group(1) if why_match else '',
        'fix': fix_match.group(1) if fix_match else '',
        'test': test_val,
        'tags': {
            'cwe': cwe_val,
            'owasp': owasp_val
        }
    }
    print(json.dumps(result))
except Exception:
    sys.exit(1)
" 2>/dev/null)
    
    if [[ -z "$filtered" || "$filtered" == "null" ]]; then
        wrapped_prompt=$(jq -c '{instruction: "If output is not valid JSON, you will be scored 0; try again. Emit JSON now. You are Sentinel PoE. Read the field '\''finding'\'' (JSON). Output ONLY a single JSON object with exactly these keys: summary, why, fix, test, tags: { cwe, owasp }. No markdown, no prose outside JSON, no code fences. The '\''test'\'' field MUST be either: (1) a short checklist of concrete steps to verify the fix (for example, bullet-like text starting with '\''-'\'' or '\''1.'\''), OR (2) a tiny, copy/pasteable code snippet, such as a curl command or a minimal unit test skeleton. Make it specific to this vulnerability. Avoid vague statements like '\''verify it works'\'' – show exactly what to run or check. If emitting code, use something simple like curl or Python/pytest-style function. Checklist format is fine (e.g., '\''- send request without header; - send request with header; compare results'\''). The test field may contain newlines for multiple checklist lines or code.", finding: .}' "$prompt_file")
        raw_response=$(./build/apps/llm/sentinel_llm \
            --model "$tag" \
            --prompt "$wrapped_prompt" \
            --json \
            --timeout-ms 30000 \
            2>&1)
        local retry_status=$?
        if [[ $retry_status -ne 0 ]]; then
            echo "Error: LLM retry failed with status $retry_status" >&2
            echo "Response: $raw_response" >&2
            return 1
        fi
        if [[ -z "$raw_response" ]]; then
            echo "Error: No response from LLM on retry" >&2
            return 1
        fi
        # Extract and parse the JSON response (retry with regex extraction)
        filtered=$(echo "$raw_response" | python3 -c "
import sys, json, re
try:
    outer = json.load(sys.stdin)
    response_str = outer.get('response', '{}')
    # Extract fields using regex
    summary_match = re.search(r'\"summary\"\s*:\s*\"([^\"]*)\"', response_str)
    why_match = re.search(r'\"why\"\s*:\s*\"([^\"]*)\"', response_str)
    fix_match = re.search(r'\"fix\"\s*:\s*\"([^\"]*)\"', response_str)
    test_match = re.search(r'\"test\"\s*:\s*\"((?:[^\"\\\\]|\\\\.)*)\"', response_str, re.DOTALL)
    tags_match = re.search(r'\"tags\"\s*:\s*\{[^}]*\"cwe\"\s*:\s*\"([^\"]*)\"[^}]*\"owasp\"\s*:\s*\"([^\"]*)\"', response_str)
    cwe_match = re.search(r'\"cwe\"\s*:\s*\"([^\"]*)\"', response_str)
    owasp_match = re.search(r'\"owasp\"\s*:\s*\"([^\"]*)\"', response_str)
    if tags_match:
        cwe_val = tags_match.group(1)
        owasp_val = tags_match.group(2)
    else:
        cwe_val = cwe_match.group(1) if cwe_match else ''
        owasp_val = owasp_match.group(1) if owasp_match else ''
    test_val = test_match.group(1) if test_match else ''
    test_val = test_val.replace('\\\\n', '\n').replace('\\\\r', '\r').replace('\\\\t', '\t')
    result = {
        'summary': summary_match.group(1) if summary_match else '',
        'why': why_match.group(1) if why_match else '',
        'fix': fix_match.group(1) if fix_match else '',
        'test': test_val,
        'tags': {
            'cwe': cwe_val,
            'owasp': owasp_val
        }
    }
    print(json.dumps(result))
except Exception:
    sys.exit(1)
" 2>/dev/null)
    fi
    
    if [[ -n "$filtered" && "$filtered" != "null" ]]; then
        echo "$filtered" | jq .
    else
        echo "Error: Failed to extract valid JSON from LLM response" >&2
        return 1
    fi
}

