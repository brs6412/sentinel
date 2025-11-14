# Sentinel Demo Guide

This guide explains how to run the Sentinel security scanner demo, both using the automated script and manually via command line.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start: Automated Demo](#quick-start-automated-demo)
3. [Manual Demo: Step-by-Step](#manual-demo-step-by-step)
4. [Understanding the Output](#understanding-the-output)
5. [Generated Files](#generated-files)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before running the demo, ensure you have:

- **Ollama** installed and running (for LLM features)
  - Default URL: `http://127.0.0.1:11434`
  - At least one model pulled (e.g., `llama3.2:3b-instruct-q4_0`)
- **Required tools**: `jq`, `curl`, `cmake`, `ctest`, `rg` (ripgrep)
- **Build dependencies**: C++17 compiler, OpenSSL, CURL, nlohmann/json

### Verify Prerequisites

```bash
# Check if Ollama is running
curl -fsS http://127.0.0.1:11434/api/tags

# Check required tools
which jq curl cmake ctest rg
```

---

## Quick Start: Automated Demo

The easiest way to run the full demo is using the automated script:

### Basic Usage

```bash
# From the repository root directory
./tools/full_demo.sh
```

This will:
1. Build the project
2. Test LLM connectivity
3. Run PoE (Proof-of-Exploit) generation
4. Start the demo server
5. Scan both insecure and secure endpoints
6. Generate all artifacts and test files
7. Display a summary of results

### Custom Model

```bash
# Use a different Ollama model
./tools/full_demo.sh llama3.1:8b
```

### What Happens During the Demo

1. **Build Phase**: Compiles all C++ code
2. **Ollama Models**: Lists available models
3. **LLM Smoke Test**: Verifies basic LLM connectivity
4. **PoE Smoke Test**: Tests proof-of-exploit generation
5. **Demo Server**: Starts a local test server on port 8080
6. **Scanner Test (Insecure)**: Scans `http://127.0.0.1:8080` for vulnerabilities
7. **Scanner Test (Secure)**: Scans `http://127.0.0.1:8080/secure` (should have fewer findings)
8. **Comparison**: Shows side-by-side results
9. **Summary**: Lists all generated files

---

## Manual Demo: Step-by-Step

If you prefer to run commands manually or understand what each step does:

### Step 1: Build the Project

```bash
# Clean build
rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

### Step 2: Verify Ollama is Running

```bash
# Check Ollama health
curl -fsS http://127.0.0.1:11434/api/tags | jq -r ".models[].name"
```

Expected output:
```
llama3.2:3b-instruct-q4_0
llama3.1:latest
```

### Step 3: Test LLM Connectivity

```bash
# Basic LLM smoke test
./build/apps/llm/sentinel_llm \
  --model llama3.2:3b-instruct-q4_0 \
  --prompt "Say 'Sentinel LLM OK' and nothing else." \
  --json
```

Expected output:
```json
{
  "response": "Sentinel LLM OK"
}
```

### Step 4: Test PoE (Proof-of-Exploit) Generation

```bash
# Generate PoE for a sample finding
./build/apps/llm/sentinel_llm \
  --model llama3.2:3b-instruct-q4_0 \
  --prompt "$(jq -c '{instruction: "...", finding: .}' apps/demo_server/fixtures/poe_prompt.sample.json)" \
  --json \
  --timeout-ms 30000
```

This tests the LLM's ability to generate structured vulnerability explanations.

### Step 5: Start the Demo Server

```bash
# Start demo server in background
./build/apps/demo_server/demo_server > /tmp/demo_server.log 2>&1 &
DEMO_PID=$!

# Wait for server to start
sleep 2

# Verify it's running
curl -fsS http://127.0.0.1:8080/health
```

### Step 6: Run Scanner on Insecure Endpoint

```bash
# Scan the insecure endpoint
./build/sentinel scan --target http://127.0.0.1:8080
```

**What this does:**
- Crawls the target URL and discovers endpoints
- Analyzes responses for security issues
- Generates findings (missing headers, unsafe cookies, etc.)
- Creates reproduction artifacts
- Logs findings to tamper-evident chain log
- Generates markdown test files
- Evaluates risk budget

**Expected output:**
```
Starting scan: run_20251114_012839
Target: http://127.0.0.1:8080
Crawling...
Finished crawl.
Generating findings...
Generated 8 findings
Generating reproduction artifacts...
  ✓ repro.sh
  ✓ repro_run_20251114_012839.cpp
Generating test files...
  ✓ 8 test file(s) in out/tests/
  Log verified: 17 entries, chain intact
Total risk points: 17 (warn: 5, block: 10)
```

**Exit codes:**
- `0` = PASS (no findings or within budget)
- `1` = WARN (findings present but within warn threshold)
- `2` = BLOCK (findings exceed block threshold)
- `3` = FATAL (error occurred)

### Step 7: Run Scanner on Secure Endpoint

```bash
# Scan the secure endpoint (should have fewer findings)
./build/sentinel scan --target http://127.0.0.1:8080/secure
```

Expected output:
```
Starting scan: run_20251114_012839
Target: http://127.0.0.1:8080/secure
Crawling...
Finished crawl.
Generating findings...
Generated 1 findings
...
Total risk points: 2 (warn: 5, block: 10)
```

### Step 8: Verify Chain Log Integrity

```bash
# Verify the tamper-evident log
./build/sentinel verify out/reports/sentinel_chain.jsonl
```

Expected output:
```
Verifying log: out/reports/sentinel_chain.jsonl
  Log verified: 18 entries, chain intact
```

### Step 9: Evaluate Budget

```bash
# Check budget compliance
./build/sentinel budget --policy config/policy.yaml out/reports/sentinel_chain.jsonl
```

### Step 10: Cleanup

```bash
# Stop demo server
kill $DEMO_PID
```

---

## Understanding the Output

### Scanner Output Breakdown

```
Starting scan: run_20251114_012839
```
- Unique run identifier based on timestamp

```
Target: http://127.0.0.1:8080
```
- The URL being scanned

```
Crawling...
Finished crawl.
```
- Discovery phase: finds all endpoints, forms, links

```
Generated 8 findings
```
- Number of security issues detected

```
Generating reproduction artifacts...
  ✓ repro.sh
  ✓ repro_run_20251114_012839.cpp
```
- Shell script and C++ test harness for reproducing findings

```
Generating test files...
  ✓ 8 test file(s) in out/tests/
```
- Markdown files with test commands and remediation steps

```
Log verified: 17 entries, chain intact
```
- Tamper-evident log verification passed

```
Total risk points: 17 (warn: 5, block: 10)
```
- Risk score calculation:
  - **17** = Total points from all findings
  - **warn: 5** = Warning threshold
  - **block: 10** = Blocking threshold
  - Since 17 > 10, exit code will be 2 (BLOCK)

### PoE Output Breakdown

```
Finding: Missing X-Frame-Options header

Why: The API endpoint is vulnerable to Clickjacking attacks...

Fix: Add the X-Frame-Options header with a value of 'DENY'...

Test: - Send request without X-Frame-Options header...
      - Add X-Frame-Options header...
      - Verify response headers...

CWE: <missing> | OWASP: <missing>
```
- Structured explanation of the vulnerability
- Why it's a problem
- How to fix it
- How to test the fix
- Security taxonomy tags (CWE, OWASP)

---

## Generated Files

After running the demo, you'll find files in several locations:

### 1. `runlogs/` - Demo Execution Logs

Timestamped logs from the demo script:
- `models-YYYYMMDD-HHMMSS.txt` - List of Ollama models
- `llm_smoke-YYYYMMDD-HHMMSS.json` - LLM connectivity test results
- `poe_smoke-YYYYMMDD-HHMMSS.json` - PoE generation results
- `demo_server-YYYYMMDD-HHMMSS.log` - Demo server output

### 2. `artifacts/` - Reproduction Artifacts

- `repro.sh` - Shell script with functions to reproduce each finding
- `repro_<run_id>.cpp` - Catch2 test harness for automated testing
- `vuln_findings.jsonl` - JSON Lines file with all findings
- `scan_results.jsonl` - Raw crawl results

### 3. `out/tests/` - Test Files

One markdown file per finding:
- `finding_1.md`, `finding_2.md`, etc.
- Each contains:
  - Finding ID, URL, severity, category
  - Test command (bash snippet)
  - Remediation instructions

Example (`out/tests/finding_1.md`):
```markdown
# Test: missing_security_header

**Finding ID:** finding_1
**Target URL:** http://127.0.0.1:8080/
**Severity:** medium
**Category:** missing_security_header

## Test Command

```bash
curl -s -D - http://127.0.0.1:8080/ | grep -iE '^X-Frame-Options:'
```

## Remediation

Add the `X-Frame-Options` header to responses.
Example: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`
```

### 4. `out/reports/` - Chain Logs

- `sentinel_chain.jsonl` - Tamper-evident log file
  - Each line is a JSON object with:
    - `event_type`: Type of event (e.g., "finding_recorded")
    - `timestamp`: ISO8601 timestamp
    - `payload`: Finding data
    - `prev_hash`: Hash of previous entry
    - `entry_hash`: Hash of this entry
  - If any entry is modified, verification will fail

### 5. `logs/` - Legacy Logs

- `scan.log.jsonl` - Legacy scan log (deprecated, use `out/reports/`)

---

## Troubleshooting

### Ollama Not Running

**Error:** `Error: Ollama server is not reachable`

**Solution:**
```bash
# Start Ollama (if installed via Ollama.app, it should auto-start)
# Or run manually:
ollama serve

# Verify it's running
curl http://127.0.0.1:11434/api/tags
```

### Model Not Found

**Error:** `Error: model 'llama3.2:3b-instruct-q4_0' not found`

**Solution:**
```bash
# Pull the model
ollama pull llama3.2:3b-instruct-q4_0

# Or use a different model you have
./tools/full_demo.sh llama3.1:latest
```

### Demo Server Port Already in Use

**Error:** `Error: demo_server did not respond`

**Solution:**
```bash
# Find what's using port 8080
lsof -i :8080

# Kill the process or use a different port
# (You'd need to modify demo_server code to change port)
```

### Build Failures

**Error:** Compilation errors

**Solution:**
```bash
# Clean and rebuild
rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# Check for missing dependencies
# - OpenSSL: brew install openssl@3
# - CURL: Usually pre-installed on macOS
# - nlohmann/json: brew install nlohmann-json
```

### Policy File Parsing Error

**Error:** `Error parsing policy file: [json.exception.parse_error...]`

**Solution:**
- The policy file should be YAML format (not JSON)
- Check `config/policy.yaml` syntax
- The code will fall back to defaults if parsing fails

### Chain Verification Fails

**Error:** `Warning: Chain verification failed`

**Solution:**
- This means the log file was tampered with
- If you manually edited `out/reports/sentinel_chain.jsonl`, verification will fail
- This is expected behavior - the chain is designed to detect tampering
- Delete the file and run a fresh scan to start a new chain

---

## Next Steps

After running the demo:

1. **Review Findings**: Check `out/tests/*.md` files for detailed test instructions
2. **Reproduce Issues**: Use `artifacts/repro.sh` to manually test findings
3. **Fix Vulnerabilities**: Apply remediation steps from test files
4. **Re-scan**: Run scanner again to verify fixes
5. **Integrate**: Use exit codes in CI/CD pipelines to gate deployments

---

## Additional Resources

- **LLM Integration**: See `apps/llm/README-LLM.md` for LLM-specific documentation
- **Policy Configuration**: Edit `config/policy.yaml` to adjust risk thresholds
- **Scanner Configuration**: Edit `config/scanner.yaml` for crawler settings

---

## Summary

The Sentinel demo showcases:
- ✅ Automated vulnerability discovery
- ✅ Tamper-evident audit logging
- ✅ Reproducible test generation
- ✅ Risk-based CI/CD gating
- ✅ LLM-assisted vulnerability explanation

All generated files are designed to be actionable - use the test files to verify fixes and the chain logs for compliance auditing.

