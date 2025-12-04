Sentinel: Phase 3 Overview and How to Run It
===========================================

Sentinel is a Dynamic Application Security Testing (DAST) system for web applications and APIs. It detects and reproduces vulnerabilities with verifiable proofs, CI integration, and LLM-assisted payload generation.

Root Files:
CMakeLists.txt, Makefile – Build configuration
.clang-format, .editorconfig, .pre-commit-config.yaml – Code style
ci_policy.yml – CI risk budget rules
docker-compose.yml – Containerized setup
README.md – Developer guide
docs/PHASE3_README.txt – This file (overview and usage)

.github/workflows/:
fixture-e2e.yml – End-to-end test automation
sentinel-scan.yml – CI scan execution

apps/:
demo_server/ – Local test server with insecure and secure endpoints
  fixtures/ – Sample endpoints, findings, and PoE prompts
llm/ – LLM integration module (Ollama client, PoE renderer)
  README-LLM.md – LLM module documentation

config/:
payloads.yaml – Vulnerability payload templates
policy.yaml – Risk scoring thresholds and budget configuration
scanner.yaml – Crawler and scan settings

src/:
core/ – crawler.cpp, http_client.cpp, vuln_engine.cpp: site exploration, requests, and detection
artifacts/ – artifacts.cpp: proof-of-exploit generation
budget/ – policy.cpp, policy.h: CI policy enforcement and risk budgeting
logging/ – chain.cpp, chain.h: tamper-evident hash-chained JSONL logs
llm/ – ollama_client.h, poe_renderer.h, prompt_templates.h: LLM integration headers
main.cpp – Entry point
sentinel_llm.cpp – LLM CLI implementation
reporter_stub.cpp – Reporting stub

tests/:
Unit tests (test_artifacts.cpp, test_budget.cpp, test_chain.cpp, test_ollama_client.cpp, test_poe_renderer.cpp) using Catch2

docker/:
certs/ – TLS keys for demo
nginx.conf – Reverse proxy config

out/:
artifacts/, reports/ – Generated scan logs, manifests, and chain logs
tests/ – Per-finding Markdown test files

tools/:
full_demo.sh – End-to-end demo script
full_tests.sh – Full LLM test suite runner
lib.sh – Shared helper functions
check_demo.sh, gen-selfsigned.sh – Setup helpers
sentinel_validate.cpp – Artifact verification
tf_safety_scorer/ – Python LLM safety filter (safety_scorer.py, requirements.txt)
repo_tree.c, repo_tree_ignore.c – Repository tree utilities

third_party/:
httplib.h – External HTTP library

----------------------------------------
What Sentinel Does Today
----------------------------------------

High‑level capabilities:

- **Crawling and exploration**
  - Discovers URLs, methods, parameters, and cookies.
  - Writes crawl results to JSON artifacts under `artifacts/`.

- **Vulnerability detection**
  - Focuses on HTTP‑level and header‑level issues that match common CWE/OWASP themes:
    - Missing or weak security headers (e.g., `X-Frame-Options`, `Content-Security-Policy`).
    - Unsafe cookies (missing `Secure`, `HttpOnly`, or proper `SameSite`).
    - CORS misconfiguration.
  - Each finding is stored as a structured JSON object with:
    - `category`, `severity`, `confidence`, `url`, and `evidence`.
    - Mapped tags such as `cwe`, `owasp`, and short remediation text.

- **Reproducible proofs and artifacts**
  - For each finding, Sentinel generates:
    - A runnable `curl` command and/or Catch2 test harness (`artifacts/repro*.cpp`).
    - A Markdown test file in `out/tests/<finding-id>.md` with:
      - The target URL.
      - A one‑liner shell test (e.g., `curl | grep <header>`).
      - A short remediation summary.

- **Tamper‑evident logging**
  - Every recorded finding is written to an **append‑only, hash‑chained JSONL log**:
    - `out/reports/sentinel_chain.jsonl`
  - Each line includes:
    - Event payload (finding data).
    - `prev_hash` and `entry_hash` that form a chain.
  - A verification step recomputes the chain and warns if any line has been tampered with.

- **Risk budgeting and CI exit codes**
  - Loads a policy from `config/policy.yaml` that defines:
    - A **risk budget** in points.
    - Per‑severity weights and per‑category scores.
  - Computes a total risk score from the findings and returns an exit code that encodes the result:
    - `0` – No findings (or below minimum thresholds).
    - `1` – Findings present but within the configured budget.
    - `2` – Risk budget exceeded (CI should block).
    - `3` – Fatal errors (e.g., configuration or parsing failure).

- **LLM‑assisted PoE (Proof‑of‑Exploit) suggestions**
  - Uses a local LLM (via Ollama) to:
    - Summarize a finding in natural language.
    - Suggest a concise fix and a **concrete test** (checklist or small code snippet).
    - Tag the finding with `cwe` and `owasp`.
  - The LLM response is constrained to a strict JSON shape:
    - `{ "summary": "...", "why": "...", "fix": "...", "test": "...", "tags": { "cwe": "...", "owasp": "..." } }`
  - Non‑JSON or malformed output is retried with stricter instructions or discarded; deterministic logic always has the final say.

----------------------------------------
Installing Dependencies
----------------------------------------

The easiest way to install all dependencies is to run the installation script:

```bash
./tools/install_dependencies.sh
```

This script detects your operating system and installs the required packages. It supports:
- Debian/Ubuntu (apt)
- macOS (Homebrew)
- Fedora/RHEL (dnf/yum)
- Arch Linux (pacman)

Note: The installation script will check for Ollama but cannot install it automatically. You must install Ollama manually from https://ollama.ai and ensure it is running before using Sentinel.

Alternatively, you can install dependencies manually:

On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libcurl4-openssl-dev libgumbo-dev nlohmann-json3-dev libssl-dev jq curl ripgrep python3 python3-pip
```

On macOS:
```bash
brew install cmake gumbo-parser nlohmann-json openssl jq curl ripgrep python3
```

Ollama is required for LLM features. Install it from https://ollama.ai, then start the server:
```bash
ollama serve
```

Set the Ollama host environment variable:
```bash
export OLLAMA_HOST=http://127.0.0.1:11434
```

----------------------------------------
How to Build
----------------------------------------

From the repository root (`sentinel/`):

```bash
rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

This produces:

- Core scanner binary: `build/sentinel`
- Demo server: `build/apps/demo_server/demo_server`
- LLM CLI: `build/apps/llm/sentinel_llm`
- Unit tests: `build/test_*`

----------------------------------------
How to Run the Tests
----------------------------------------

There are two main ways to run tests: **quick unit tests** and the **LLM‑focused test harness**.

1) Quick unit tests via CTest
-----------------------------

From `build/`:

```bash
cd build
ctest -N                # list all tests
ctest -R "budget|chain" # run specific suites
ctest                   # run all tests
```

These cover:

- Hash‑chained logging (`test_chain*`).
- Risk budget evaluation (`test_budget`).
- Ollama client and PoE renderer behavior.

2) Full LLM test suite
----------------------

Prerequisites:

- Ollama must be installed and serving locally:

  ```bash
  ollama serve
  ```

- Set the Ollama host environment variable:

  ```bash
  export OLLAMA_HOST=http://127.0.0.1:11434
  ```

Run the full LLM test script from the repo root:

```bash
./tools/full_tests.sh
```

This script:

- Ensures `build/` exists and binaries are built.
- Discovers tests via `ctest -N`.
- Runs all `ollama|poe|llm` tests with verbose output.
- Runs individual Catch2 binaries:
  - `test_ollama_client`
  - `test_poe_renderer`
  - `test_llm_poe_smoke` (if present)
- Saves logs under `runlogs/` with timestamps.
- Prints a PASS/FAIL summary at the end.

You can also pass a different LLM model tag:

```bash
./tools/full_tests.sh llama3.1:8b
```

----------------------------------------
How to Run the End‑to‑End Demo
----------------------------------------

The demo exercises:

- The **demo server** with both insecure and secure endpoints.
- The **scanner**, including crawling, detection, and artifact generation.
- The **LLM PoE pipeline**.
- The **chain logger** and **risk budget**.

1) Ensure Ollama is running
----------------------------

Ollama must be installed and running. Start the server if it's not already running:

```bash
ollama serve
```

Set the Ollama host environment variable:

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
```

2) Run the full demo script
---------------------------

From the repo root:

```bash
./tools/full_demo.sh
```

You can optionally provide a model tag:

```bash
./tools/full_demo.sh llama3.2:3b-instruct-q4_0
```

The script will:

- Check for required tools: `jq`, `curl`, `cmake`, `ctest`, `rg`.
- Ensure `runlogs/` exists and a build is available.
- Warm the chosen LLM model via a small, non‑destructive request.
- Log the list of available Ollama models to `runlogs/models-<timestamp>.txt`.
- Run:
  - An LLM smoke test via `apps/llm/sentinel_llm`.
  - A PoE smoke test that produces a structured JSON object with summary, fix, and test.
- Start the demo server (`apps/demo_server/demo_server`) and verify it responds on:
  - `http://127.0.0.1:8080/` (insecure routes).
  - `http://127.0.0.1:8080/secure` (secure route).
- Run the scanner against:
  - Insecure endpoints (expect findings, non‑zero risk points, non‑zero exit code).
  - The `/secure` endpoint (expect 0 findings, 0 points, exit code 0).
- Print:
  - A PoE summary line (short human‑readable description).
  - A final line showing findings count, total risk points, and exit code.

3) Where to Look After the Demo
-------------------------------

After `./tools/full_demo.sh` completes, you should see:

- **Artifacts and findings**
  - `artifacts/vuln_findings.jsonl`
    - Structured per‑finding JSON records.
  - `artifacts/repro.sh`
    - A shell script with runnable reproduction commands.
  - `artifacts/repro_<run-id>.cpp`
    - A Catch2 test file for compiled repro tests.

- **Per‑finding tests**
  - `out/tests/<finding-id>.md`
    - One file per finding, each with:
      - Target URL.
      - A copy/pasteable test command (usually `curl`‑based).
      - A brief remediation summary.

- **Chain log**
  - `out/reports/sentinel_chain.jsonl`
    - Hash‑chained log of `finding_recorded` events.
    - Can be re‑verified by the scanner's chain verification step.

- **Run logs**
  - `runlogs/llm_smoke-<timestamp>.json`
  - `runlogs/poe_smoke-<timestamp>.json` and `runlogs/poe_smoke.json`
  - `runlogs/demo_server-<timestamp>.log`
  - `runlogs/models-<timestamp>.txt`

These files let you:

- Inspect what the scanner saw.
- Reproduce findings by copy/pasting commands or running generated tests.
- Confirm that the chain log has not been tampered with.
- Check how the risk budget translated into an exit code for CI.

----------------------------------------
Quick Mental Model
----------------------------------------

In short:

- Sentinel crawls a target and finds interesting HTTP surfaces.
- It runs a set of safe, structured checks and records only **confirmed** findings.
- Every confirmed finding:
  - Is logged in a hash chain.
  - Has tags (CWE, OWASP) and remediation hints.
  - Gets an associated Markdown test file and optional Catch2 test.
- A local LLM can suggest better summaries, fixes, and tests, but:
  - It must speak strict JSON.
  - Its output is always validated and can be ignored.
- A risk budget policy turns findings into a single exit code that CI can trust.

Taken together, this gives you a DAST tool that is more **reproducible**, more **auditable**, and easier for developers to use than a firehose of scanner warnings.
