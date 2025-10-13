.PHONY: lint-config

lint-config:
	python -c 'import yaml; yaml.safe_load(open("config/policy.yaml")); yaml.safe_load(open("config/scanner.yaml")); print("OK")'

.PHONY: lint-fixtures lint
FIX_ENDPTS=apps/demo_server/fixtures/endpoints.small.jsonl
FIX_FINDINGS=apps/demo_server/fixtures/findings.demo.jsonl

lint-fixtures:
	@while read -r l; do python -c 'import json,sys; json.loads(sys.argv[1])' "$$l" || exit 1; done < $(FIX_ENDPTS)
	@while read -r l; do python -c 'import json,sys; json.loads(sys.argv[1])' "$$l" || exit 1; done < $(FIX_FINDINGS)
	@echo OK

lint: lint-config lint-fixtures

.PHONY: build-demo run-demo
build-demo:
\tcmake -S . -B build && cmake --build build -j

run-demo: build-demo
\t./build/apps/demo_server/demo_server
