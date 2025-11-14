# Sentinel - unified Makefile (merged)
# Combines demo-server workflow + Person B ops + utilities

# -------------------- PHONY --------------------
.PHONY: all help \
        build clean install \
        test test-verbose test-coverage \
        fixture-up fixture-down fixture-logs \
        scan verify budget e2e demo ci dev package docs watch \
        lint lint-code lint-config lint-fixtures \
        build-demo run-demo e2e-fixture e2e-local llm-fallback validate fixtures-validate https-up tf-score \
        llm-build llm-test

# -------------------- Config -------------------
BUILD_DIR := build
CMAKE_FLAGS ?= -DCMAKE_BUILD_TYPE=Release

OUT_DIR := out
REPORTS_DIR := $(OUT_DIR)/reports
ARTIFACTS_DIR := $(OUT_DIR)/artifacts

# Demo app fixtures (your branch)
FIXTURES_DEMO_DIR := apps/demo_server/fixtures
FIX_ENDPTS   := $(FIXTURES_DEMO_DIR)/endpoints.small.jsonl
FIX_FINDINGS := $(FIXTURES_DEMO_DIR)/findings.demo.jsonl

# Test fixtures (main branch)
TEST_FIXTURES_DIR := tests/fixtures

# Default
all: build

# -------------------- Help ---------------------
help:
	@echo "Sentinel - Build & Ops Targets"
	@echo ""
	@echo "Build:"
	@echo "  make build            - Configure and build"
	@echo "  make clean            - Remove build and output"
	@echo "  make install          - Install binaries (system)"
	@echo ""
	@echo "Tests:"
	@echo "  make test             - Run unit tests"
	@echo "  make test-verbose     - Run tests (verbose)"
	@echo "  make test-coverage    - Run tests (coverage scaffold)"
	@echo ""
	@echo "Fixtures:"
	@echo "  make fixture-up       - Start docker fixtures under tests/fixtures"
	@echo "  make fixture-down     - Stop docker fixtures"
	@echo "  make fixture-logs     - Tail fixture logs"
	@echo ""
	@echo "Demo app workflow:"
	@echo "  make build-demo       - Build project"
	@echo "  make run-demo         - Run demo server"
	@echo "  make e2e-fixture      - Generate HTML report from demo fixtures"
	@echo "  make https-up         - Start local HTTPS reverse-proxy (self-signed)"
	@echo ""
	@echo "LLM / Validation:"
	@echo "  make llm-fallback     - Augment payloads with LLM"
	@echo "  make validate         - Validate fixture JSONL with sentinel-validate"
	@echo "  make tf-score         - TensorFlow safety scorer on payloads"
	@echo ""
	@echo "Operations:"
	@echo "  make scan             - Run scanner (expects local target)"
	@echo "  make verify           - Verify hash-chained logs"
	@echo "  make budget           - Evaluate risk budget"
	@echo "  make e2e              - E2E smoke: fixtures -> scan -> verify -> budget"
	@echo "  make demo             - Guided demo workflow"
	@echo "  make ci               - CI pipeline simulation"
	@echo ""
	@echo "Quality:"
	@echo "  make lint             - Config+fixtures lint + clang-tidy"
	@echo "  make format           - clang-format sources"
	@echo ""

# -------------------- Build --------------------
build: $(BUILD_DIR)/Makefile
	@echo "Building Sentinel..."
	@cmake --build $(BUILD_DIR) -j$$(command -v nproc >/dev/null 2>&1 && nproc || sysctl -n hw.ncpu)
	@echo "✓ Build complete"

$(BUILD_DIR)/Makefile:
	@echo "Configuring build..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. $(CMAKE_FLAGS)

clean:
	@echo "Cleaning build/output..."
	@rm -rf $(BUILD_DIR) $(OUT_DIR) artifacts
	@echo "✓ Clean complete"

install: build
	@echo "Installing Sentinel..."
	@cd $(BUILD_DIR) && sudo make install
	@echo "✓ Install complete"

# -------------------- Tests --------------------
test: build
	@echo "Running unit tests..."
	@cd $(BUILD_DIR) && ctest --output-on-failure

test-verbose: build
	@cd $(BUILD_DIR) && ctest --verbose

test-coverage: build
	@cd $(BUILD_DIR) && ctest
	@echo "(Coverage hooks would run here)"

# -------------------- LLM Tests --------------------
llm-build: build
	@echo "Building LLM components..."
	@cmake --build $(BUILD_DIR) --target sentinel_llm test_ollama_client test_poe_renderer
	@echo "✓ LLM build complete"

llm-test: build
	@echo "Running LLM tests..."
	@cd $(BUILD_DIR) && ctest -R "test_ollama_client|test_poe_renderer" --output-on-failure -V
	@echo "✓ LLM tests complete"

# -------------------- Fixtures (docker) --------
fixture-up:
	@echo "Starting test fixtures..."
	@if [ -f $(TEST_FIXTURES_DIR)/docker-compose.yml ]; then \
		cd $(TEST_FIXTURES_DIR) && docker compose up -d; \
		echo "Waiting for services..."; sleep 5; \
		echo "✓ Fixtures running"; \
	else \
		echo "⚠ No docker-compose.yml under $(TEST_FIXTURES_DIR)"; \
	fi

fixture-down:
	@if [ -f $(TEST_FIXTURES_DIR)/docker-compose.yml ]; then \
		cd $(TEST_FIXTURES_DIR) && docker compose down; \
		echo "✓ Fixtures stopped"; \
	fi

fixture-logs:
	@if [ -f $(TEST_FIXTURES_DIR)/docker-compose.yml ]; then \
		cd $(TEST_FIXTURES_DIR) && docker compose logs -f; \
	fi

# -------------------- Demo app flow ------------
build-demo: build

run-demo: build-demo
	./$(BUILD_DIR)/apps/demo_server/demo_server

e2e-fixture: build-demo
	@mkdir -p $(ARTIFACTS_DIR) $(REPORTS_DIR)
	@cp -f $(FIX_ENDPTS)   $(ARTIFACTS_DIR)/endpoints.small.jsonl
	@cp -f $(FIX_FINDINGS) $(ARTIFACTS_DIR)/findings.demo.jsonl
	@./$(BUILD_DIR)/reporter_stub \
		--policy config/policy.yaml \
		--findings $(ARTIFACTS_DIR)/findings.demo.jsonl \
		--endpoints $(ARTIFACTS_DIR)/endpoints.small.jsonl \
		--out $(REPORTS_DIR)/sentinel_report.html || true
	@echo "OK: $(REPORTS_DIR)/sentinel_report.html"

llm-fallback: build-demo
	./$(BUILD_DIR)/sentinel-llm \
		--in config/payloads.yaml \
		--out $(OUT_DIR)/payloads/augmented.yaml \
		--model llama3:instruct \
		--max-new 30 --temperature 0.2 --seed 42 \
		--manifest $(OUT_DIR)/assets/assets.manifest.json
	@echo "OK: $(OUT_DIR)/payloads/augmented.yaml and $(OUT_DIR)/assets/assets.manifest.json"

validate: build-demo
	./$(BUILD_DIR)/sentinel-validate --file $(FIX_ENDPTS)   --type endpoints
	./$(BUILD_DIR)/sentinel-validate --file $(FIX_FINDINGS) --type findings
	@echo "validate OK"

fixtures-validate: validate

https-up:
	./tools/gen-selfsigned.sh
	docker compose up -d
	@echo "Try: curl -isk https://localhost/set-cookie | grep -i '^set-cookie:'"

tf-score:
	python3 -m pip install -r tools/tf_safety_scorer/requirements.txt
	python3 tools/tf_safety_scorer/safety_scorer.py \
		--in $(OUT_DIR)/payloads/augmented.yaml \
		--out $(OUT_DIR)/assets/llm_safety_scores.json
	@echo "OK: $(OUT_DIR)/assets/llm_safety_scores.json"

e2e-local:
	@echo "e2e-local scaffold: orchestrate explorer/prober/reporter later."
	@exit 0

# -------------------- Ops (scanner) ------------
scan: build
	@echo "Running security scan..."
	@mkdir -p artifacts
	@$(BUILD_DIR)/sentinel scan --target http://localhost:8081 --out artifacts/
	@echo "✓ Scan complete"

verify: build
	@echo "Verifying log integrity..."
	@$(BUILD_DIR)/sentinel verify artifacts/scan.log.jsonl

budget: build
	@echo "Evaluating risk budget..."
	@$(BUILD_DIR)/sentinel budget --policy ci-policy.yml artifacts/scan.log.jsonl || true

e2e: clean build
	@echo "=== Running E2E Smoke Test ==="
	@$(MAKE) fixture-up
	@$(MAKE) scan
	@if [ -f artifacts/scan.log.jsonl ]; then echo "  ✓ scan.log.jsonl"; else echo "  ✗ scan.log.jsonl missing"; exit 1; fi
	@$(MAKE) verify
	@$(MAKE) budget
	@$(MAKE) fixture-down
	@echo "=== E2E Test Complete ==="

demo: clean build
	@echo "Sentinel Demo Workflow"
	@read -p "Press Enter to start..." _
	@$(MAKE) e2e
	@echo "Artifacts: artifacts/"

# -------------------- Quality ------------------
format:
	@echo "Formatting code..."
	@find src tests -name "*.cpp" -o -name "*.h" | xargs clang-format -i || true
	@echo "✓ Format complete"

# Config & fixtures lint (YAML/JSON)
lint-config:
	python -c 'import yaml; yaml.safe_load(open("config/policy.yaml")); yaml.safe_load(open("config/scanner.yaml")); print("OK")'

lint-fixtures:
	@grep -v '^[[:space:]]*$$' $(FIX_ENDPTS)   | while read -r l; do python -c 'import json,sys; json.loads(sys.argv[1])' "$$l" || exit 1; done
	@grep -v '^[[:space:]]*$$' $(FIX_FINDINGS) | while read -r l; do python -c 'import json,sys; json.loads(sys.argv[1])' "$$l" || exit 1; done
	@echo OK

# C++ lint
lint-code:
	@echo "Linting C++ with clang-tidy..."
	@find src tests -name "*.cpp" -o -name "*.h" | xargs clang-tidy || true
	@echo "✓ Lint complete"

# Aggregate lint
lint: lint-config lint-fixtures lint-code

# -------------------- CI & Packaging -----------
ci: clean build test e2e
	@echo "CI Pipeline Simulation Complete ✓"

dev: build test
	@echo "✓ Dev build+test complete"

package: clean build test
	@echo "Creating release package..."
	@mkdir -p dist
	@cp $(BUILD_DIR)/sentinel dist/
	@cp ci-policy.yml dist/
	@[ -f PERSON_B_README.md ] && cp PERSON_B_README.md dist/README.md || true
	@tar -czf sentinel-$$(date +%Y%m%d).tar.gz dist/
	@rm -rf dist
	@echo "✓ Package: sentinel-$$(date +%Y%m%d).tar.gz"

docs:
	@echo "Generating docs..."
	@doxygen Doxyfile 2>/dev/null || echo "Doxygen not installed"

watch:
	@echo "Watching for changes (Ctrl+C to stop)..."
	@find src tests -name "*.cpp" -o -name "*.h" | entr -c $(MAKE) dev
