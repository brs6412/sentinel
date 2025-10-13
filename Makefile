.PHONY: lint-config

lint-config:
	python -c 'import yaml; yaml.safe_load(open("config/policy.yaml")); yaml.safe_load(open("config/scanner.yaml")); print("OK")'
