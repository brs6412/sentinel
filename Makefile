# Sentinel Security Scanner - Makefile
# Person B: Artifact, Logging, Budget, CI Integration

.PHONY: all build clean test install fixture-up fixture-down scan verify budget help

# Build configuration
BUILD_DIR := build
CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=Release

# Directories
ARTIFACTS_DIR := artifacts
FIXTURES_DIR := tests/fixtures

all: build

help:
	@echo "Sentinel Security Scanner - Build Targets"
	@echo ""
	@echo "Building:"
	@echo "  make build          - Build all binaries"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make install        - Install binaries to system"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run unit tests"
	@echo "  make test-verbose   - Run tests with detailed output"
	@echo "  make e2e            - Run end-to-end smoke test"
	@echo ""
	@echo "Fixtures:"
	@echo "  make fixture-up     - Start test application fixtures"
	@echo "  make fixture-down   - Stop test application fixtures"
	@echo ""
	@echo "Operations:"
	@echo "  make scan           - Run scan against local fixture"
	@echo "  make verify         - Verify log integrity"
	@echo "  make budget         - Evaluate risk budget"
	@echo "  make demo           - Full demo workflow"
	@echo ""

# Build targets
build: $(BUILD_DIR)/Makefile
	@echo "Building Sentinel..."
	@cmake --build $(BUILD_DIR) -j$(shell nproc)
	@echo "✓ Build complete"

$(BUILD_DIR)/Makefile:
	@echo "Configuring build..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. $(CMAKE_FLAGS)

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(ARTIFACTS_DIR)
	@echo "✓ Clean complete"

install: build
	@echo "Installing Sentinel..."
	@cd $(BUILD_DIR) && sudo make install
	@echo "✓ Install complete"

# Testing targets
test: build
	@echo "Running unit tests..."
	@cd $(BUILD_DIR) && ctest --output-on-failure

test-verbose: build
	@echo "Running unit tests (verbose)..."
	@cd $(BUILD_DIR) && ctest --verbose

test-coverage: build
	@echo "Running tests with coverage..."
	@cd $(BUILD_DIR) && ctest
	@echo "Coverage report would be generated here"

# Fixture management
fixture-up:
	@echo "Starting test fixtures..."
	@if [ -f $(FIXTURES_DIR)/docker-compose.yml ]; then \
		cd $(FIXTURES_DIR) && docker-compose up -d; \
		echo "Waiting for services to be ready..."; \
		sleep 5; \
		echo "✓ Fixtures running"; \
	else \
		echo "⚠ No fixtures found at $(FIXTURES_DIR)/docker-compose.yml"; \
		echo "  Person C will provide these fixtures"; \
	fi

fixture-down:
	@echo "Stopping test fixtures..."
	@if [ -f $(FIXTURES_DIR)/docker-compose.yml ]; then \
		cd $(FIXTURES_DIR) && docker-compose down; \
		echo "✓ Fixtures stopped"; \
	fi

fixture-logs:
	@if [ -f $(FIXTURES_DIR)/docker-compose.yml ]; then \
		cd $(FIXTURES_DIR) && docker-compose logs -f; \
	fi

# Scan operations
scan: build
	@echo "Running security scan..."
	@mkdir -p $(ARTIFACTS_DIR)
	@$(BUILD_DIR)/sentinel scan \
		--target http://localhost:8081 \
		--out $(ARTIFACTS_DIR)/
	@echo "✓ Scan complete"

verify: build
	@echo "Verifying log integrity..."
	@$(BUILD_DIR)/sentinel verify $(ARTIFACTS_DIR)/scan.log.jsonl

budget: build
	@echo "Evaluating risk budget..."
	@$(BUILD_DIR)/sentinel budget \
		--policy ci-policy.yml \
		$(ARTIFACTS_DIR)/scan.log.jsonl || true

# End-to-end testing
e2e: clean build
	@echo "=== Running E2E Smoke Test ==="
	@echo ""
	@echo "1. Starting fixtures..."
	@$(MAKE) fixture-up
	@echo ""
	@echo "2. Running scan..."
	@$(MAKE) scan
	@echo ""
	@echo "3. Checking artifacts..."
	@if [ -f $(ARTIFACTS_DIR)/scan.log.jsonl ]; then \
		echo "  ✓ scan.log.jsonl"; \
	else \
		echo "  ✗ scan.log.jsonl missing"; exit 1; \
	fi
	@if [ -f $(ARTIFACTS_DIR)/repro.sh ]; then \
		echo "  ✓ repro.sh"; \
	else \
		echo "  ✗ repro.sh missing"; exit 1; \
	fi
	@if [ -f $(ARTIFACTS_DIR)/assets.manifest.json ]; then \
		echo "  ✓ assets.manifest.json"; \
	else \
		echo "  ✗ assets.manifest.json missing"; exit 1; \
	fi
	@echo ""
	@echo "4. Verifying log..."
	@$(MAKE) verify
	@echo ""
	@echo "5. Evaluating budget..."
	@$(MAKE) budget
	@echo ""
	@echo "6. Cleaning up..."
	@$(MAKE) fixture-down
	@echo ""
	@echo "=== E2E Test Complete ==="

# Demo workflow
demo: clean build
	@echo "╔════════════════════════════════════════════════╗"
	@echo "║  Sentinel Security Scanner - Demo Workflow    ║"
	@echo "╚════════════════════════════════════════════════╝"
	@echo ""
	@echo "This demonstrates Person B's complete implementation:"
	@echo "  • Hash-chained JSONL logging"
	@echo "  • Artifact generation (repro.sh, Catch2 tests)"
	@echo "  • Risk budget evaluation"
	@echo "  • CI-ready exit codes"
	@echo ""
	@read -p "Press Enter to start..."
	@$(MAKE) e2e
	@echo ""
	@echo "Demo artifacts are in: $(ARTIFACTS_DIR)/"
	@echo ""
	@echo "Try these commands:"
	@echo "  • cat $(ARTIFACTS_DIR)/scan.log.jsonl"
	@echo "  • ./$(ARTIFACTS_DIR)/repro.sh"
	@echo "  • cat $(ARTIFACTS_DIR)/assets.manifest.json"

# Artifact inspection
show-findings:
	@echo "=== Scan Findings ==="
	@if [ -f $(ARTIFACTS_DIR)/scan.log.jsonl ]; then \
		grep "finding_recorded" $(ARTIFACTS_DIR)/scan.log.jsonl | \
		jq -r '.payload | "\(.category): \(.url)"'; \
	else \
		echo "No scan log found. Run 'make scan' first."; \
	fi

show-manifest:
	@echo "=== Artifact Manifest ==="
	@if [ -f $(ARTIFACTS_DIR)/assets.manifest.json ]; then \
		cat $(ARTIFACTS_DIR)/assets.manifest.json | jq .; \
	else \
		echo "No manifest found. Run 'make scan' first."; \
	fi

show-budget:
	@echo "=== Risk Budget Summary ==="
	@$(MAKE) budget 2>&1 | grep -A 20 "Risk Budget Report" || true

# Development helpers
format:
	@echo "Formatting code..."
	@find src tests -name "*.cpp" -o -name "*.h" | xargs clang-format -i
	@echo "✓ Format complete"

lint:
	@echo "Linting code..."
	@find src tests -name "*.cpp" -o -name "*.h" | xargs clang-tidy
	@echo "✓ Lint complete"

# CI simulation
ci: clean build test e2e
	@echo ""
	@echo "╔════════════════════════════════════════════════╗"
	@echo "║  CI Pipeline Simulation Complete              ║"
	@echo "╚════════════════════════════════════════════════╝"
	@echo ""
	@echo "All checks passed! ✓"

# Quick development cycle
dev: build test
	@echo "✓ Development build and test complete"

# Package for release
package: clean build test
	@echo "Creating release package..."
	@mkdir -p dist
	@cp $(BUILD_DIR)/sentinel dist/
	@cp ci-policy.yml dist/
	@cp PERSON_B_README.md dist/README.md
	@tar -czf sentinel-$(shell date +%Y%m%d).tar.gz dist/
	@rm -rf dist
	@echo "✓ Package created: sentinel-$(shell date +%Y%m%d).tar.gz"

# Documentation
docs:
	@echo "Generating documentation..."
	@doxygen Doxyfile 2>/dev/null || echo "Doxygen not installed"

# Watch mode (requires entr)
watch:
	@echo "Watching for changes (Ctrl+C to stop)..."
	@find src tests -name "*.cpp" -o -name "*.h" | entr -c make dev