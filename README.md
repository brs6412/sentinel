# Sentinel

Sentinel is a Dynamic Application Security Testing (DAST) system for web applications and APIs. It detects and reproduces vulnerabilities with verifiable proofs, CI integration, and optional LLM-assisted payload generation.

## Build Instructions

### Prerequisites
- CMake ≥ 3.18  
- C++17 compiler
- libcurl development headers and library installed  
- gumbo-parser (HTML parsing)
- nlohmann/json (JSON handling)
- libssl development headers and library installed
- jq, curl (for demo scripts)
- Ollama (optional, for LLM features)

On Debian/Ubuntu:
```bash
sudo apt install build-essential cmake libcurl4-openssl-dev libgumbo-dev nlohmann-json3-dev libssl-dev jq curl
```

On macOS:
```bash
brew install cmake gumbo-parser nlohmann-json openssl jq curl
```

### Build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Running the Demo

### Quick Start: Full Demo Script

The easiest way to see Sentinel in action is to run the full demo script, which performs an end-to-end demonstration:

```bash
./tools/full_demo.sh
```

Or specify a custom Ollama model:
```bash
./tools/full_demo.sh llama3.1:8b
```

**Prerequisites:**
- Ollama must be running (either via `ollama serve` or Ollama.app)
- Set `OLLAMA_HOST` environment variable if using a non-default location:
  ```bash
  export OLLAMA_HOST=http://127.0.0.1:11434
  ```

**What the Demo Does:**

1. **Ollama Models** - Lists available LLM models
2. **LLM Smoke Test** - Tests basic LLM connectivity with a simple prompt
3. **PoE Smoke Test** - Generates a Proof-of-Exploit (PoE) explanation for a sample finding
4. **Demo Server Test** - Starts a local demo server with intentionally insecure endpoints
5. **Scanner Test (Insecure)** - Scans the insecure endpoint and generates findings
6. **Secure Scanner Test** - Scans a secure endpoint for comparison
7. **Comparison** - Shows side-by-side comparison of secure vs insecure results

**Understanding the Output:**

```
=== Scanner Test (Insecure Endpoint) ===
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

**What this means:**
- **Generated 8 findings**: The scanner found 8 security issues
- **repro.sh**: Shell script to reproduce each finding
- **repro_*.cpp**: C++ test harness for automated testing
- **8 test file(s)**: Markdown files in `out/tests/` with test commands and remediation steps
- **Log verified**: Tamper-evident chain log verified successfully
- **Total risk points**: Risk score calculated from findings (17 points exceeds block threshold of 10)
- **Exit code**: 2 = BLOCK (risk exceeds threshold), 1 = WARN, 0 = PASS

**Exit Codes:**
- `0` = PASS: No findings or risk within acceptable limits
- `1` = WARN: Findings present but risk below block threshold
- `2` = BLOCK: Risk exceeds block threshold (should fail CI/CD)
- `3` = FATAL: Critical error (network failure, parsing error, etc.)

**Generated Files:**

After running the demo, you'll find:

- **`runlogs/`** - Demo execution logs with timestamps
  - `llm_smoke-*.json` - LLM smoke test responses
  - `poe_smoke-*.json` - PoE generation results
  - `demo_server-*.log` - Demo server logs

- **`artifacts/`** - Reproduction artifacts
  - `repro.sh` - Shell script to reproduce findings
  - `repro_<run_id>.cpp` - C++ test harness
  - `vuln_findings.jsonl` - All findings in JSONL format
  - `scan_results.jsonl` - Raw crawl results

- **`out/tests/`** - Per-finding test files
  - `finding_<id>.md` - Markdown files with:
    - Target URL
    - Test command (bash snippet)
    - Remediation instructions

- **`out/reports/`** - Tamper-evident logs
  - `sentinel_chain.jsonl` - Hash-chained log of all findings (tamper detection)

### Manual Command-Line Usage

#### Basic Scan

Scan a target URL:

```bash
./build/sentinel scan --target http://example.com
```

**Output:**
```
Starting scan: run_20251114_012839
Target: http://example.com
Crawling...
Finished crawl.
Generating findings...
Generated 8 findings
Generating reproduction artifacts...
  ✓ repro.sh
  ✓ repro_run_20251114_012839.cpp
Generating test files...
  ✓ 8 test file(s) in out/tests/
  Log verified: 8 entries, chain intact
Total risk points: 17 (warn: 5, block: 10)
```

**What happens:**
1. **Crawling**: Discovers URLs and endpoints by following links and parsing HTML
2. **Generating findings**: Analyzes responses for security issues (missing headers, unsafe cookies, CORS misconfigurations, etc.)
3. **Generating artifacts**: Creates reproduction scripts and test files
4. **Chain logging**: Logs each finding to tamper-evident chain log
5. **Budget evaluation**: Calculates risk score and determines exit code

#### Scan with OpenAPI Specification

If you have an OpenAPI spec, you can provide it to discover more endpoints:

```bash
./build/sentinel scan --target http://api.example.com --openapi openapi.json
```

#### Custom Output File

Save crawl results to a specific file:

```bash
./build/sentinel scan --target http://example.com --out my_scan.jsonl
```

#### Verify Chain Log Integrity

Check if the chain log has been tampered with:

```bash
./build/sentinel verify out/reports/sentinel_chain.jsonl
```

**Output:**
```
Verifying log: out/reports/sentinel_chain.jsonl
  Log verified: 17 entries, chain intact
```

If tampering is detected:
```
Verifying log: out/reports/sentinel_chain.jsonl
  Hash mismatch at entry 5
  Expected: sha256:abc123...
  Computed: sha256:def456...
Verification failed
```

#### Evaluate Budget Compliance

Check if findings comply with risk budget policy:

```bash
./build/sentinel budget --policy config/policy.yaml out/reports/sentinel_chain.jsonl
```

**Output:**
```
=== Risk Budget Report ===

Findings by Category:
  missing_security_header    Count:   5 Score: 10
  unsafe_cookie              Count:   2 Score: 2
  cors_misconfiguration      Count:   1 Score: 3

Total Score: 15
Status: BLOCK

   BLOCKED: Risk score exceeds threshold
```

### Understanding Test Files

Each finding generates a markdown test file in `out/tests/<finding_id>.md`:

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

These files provide:
- **Test Command**: Copy-pasteable bash command to verify the issue
- **Remediation**: Specific steps to fix the vulnerability

### Understanding Chain Logs

The chain log (`out/reports/sentinel_chain.jsonl`) is a tamper-evident append-only log. Each entry includes:

- `event_type`: Type of event (e.g., "finding_recorded")
- `timestamp`: ISO8601 UTC timestamp
- `prev_hash`: Hash of previous entry (creates the chain)
- `entry_hash`: Hash of this entry's content
- `payload`: Finding data

**Why it matters:** If someone modifies or deletes entries, the hash chain breaks and verification fails. This is useful for audit trails and compliance.

### Demo Server

The demo includes a test server with intentionally insecure endpoints:

```bash
./build/apps/demo_server/demo_server
```

**Endpoints:**
- `http://127.0.0.1:8080/` - Insecure endpoint (missing headers, unsafe cookies)
- `http://127.0.0.1:8080/secure` - Secure endpoint (all headers present, secure cookies)

Use these to test the scanner and see the difference between secure and insecure configurations.

## Configuration

### Risk Budget Policy

Edit `config/policy.yaml` to configure risk thresholds:

```yaml
risk_budget:
  max_points: 10
  weights:
    low: 1
    medium: 2
    high: 4
    critical: 8

category_scores:
  missing_security_header: 2
  unsafe_cookie: 1
  cors_misconfiguration: 3
  reflected_xss: 5
  csrf: 4
  idor: 4

warn_threshold: 3
block_threshold: 5
```

- **max_points**: Maximum acceptable risk score
- **weights**: Points per severity level
- **category_scores**: Points per finding category
- **warn_threshold**: Score threshold for warnings
- **block_threshold**: Score threshold for blocking CI/CD

## Troubleshooting

### "Ollama not reachable"

Make sure Ollama is running:
```bash
ollama serve
```

Or check if it's running on a different host:
```bash
export OLLAMA_HOST=http://your-host:11434
```

### "Error parsing policy file"

The policy file supports both JSON and YAML formats. If you see parsing errors, check:
- File syntax is valid YAML or JSON
- File path is correct (default: `config/policy.yaml`)

### "Chain verification failed"

This means the chain log has been modified. Possible causes:
- Manual editing of `sentinel_chain.jsonl`
- File corruption
- Concurrent writes (shouldn't happen in normal operation)

If verification fails, the log should be considered compromised and a new scan should be run.

## Next Steps

- Review findings in `artifacts/vuln_findings.jsonl`
- Run test commands from `out/tests/*.md` files
- Check chain log integrity with `sentinel verify`
- Integrate into CI/CD pipeline using exit codes
