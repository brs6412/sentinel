Sentinel is a Dynamic Application Security Testing (DAST) system for web applications and APIs. It detects and reproduces vulnerabilities with verifiable proofs, CI integration, and optional LLM-assisted payload generation.

Root Files:
CMakeLists.txt, Makefile – Build configuration
.clang-format, .editorconfig, .pre-commit-config.yaml – Code style
ci_policy.yml – CI risk budget rules
docker-compose.yml – Containerized setup
README.md – Developer guide

.github/workflows/:
fixture-e2e.yml – End-to-end test automation
sentinel-scan.yml – CI scan execution

apps/:
demo_server/ – Local test server with fixtures (endpoints.small.jsonl, findings.demo.jsonl)
llm/ – Placeholder for LLM integration module

config/:
payloads.yaml – Vulnerability payload templates
policy.yaml – Risk scoring thresholds
scanner.yaml – Crawler and scan settings

src/:
core/ – crawler.cpp, http_client.cpp: site exploration and requests
artifacts/ – artifacts.cpp: proof generation
budget/ – policy.cpp: CI policy enforcement
logging/ – chain.cpp: tamper-evident JSONL logs
sentinel_llm.cpp – Ollama integration
main.cpp – Entry point

tests/:
Unit tests (test_artifacts.cpp, test_budget.cpp, test_chain.cpp) using Catch2

docker/:
certs/ – TLS keys for demo
nginx.conf – Reverse proxy config

out/:
artifacts/, assets/, payloads/, reports/ – Generated scan logs, manifests, and HTML reports

tools/:
check_demo.sh, gen-selfsigned.sh – Setup helpers
sentinel_validate.cpp – Artifact verification
tf_safety_scorer/ – Python LLM safety filter (safety_scorer.py)

third_party/:
httplib.h – External HTTP library
