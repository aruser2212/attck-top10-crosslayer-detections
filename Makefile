PYTHON ?= .venv/bin/python
ELASTIC_URL ?= http://127.0.0.1:19200

.PHONY: setup check check-network check-elastic coverage lab-up lab-down

setup:
	python3 -m venv .venv
	$(PYTHON) -m pip install --require-hashes -r requirements-dev.lock

check:
	$(PYTHON) tools/validate_repo.py
	$(PYTHON) tools/check_attack.py check
	$(PYTHON) tools/generate_elastic_queries.py --check
	$(PYTHON) -m pytest -m 'not network and not integration' --junitxml=artifacts/unit-tests.xml
	$(PYTHON) tools/generate_coverage.py --check --json-output artifacts/inventory.json

check-network:
	mkdir -p artifacts
	$(PYTHON) tools/check_network.py > artifacts/network-replay.json
	cat artifacts/network-replay.json

check-elastic:
	ELASTIC_URL=$(ELASTIC_URL) $(PYTHON) -m pytest tests/integration -m integration --junitxml=artifacts/elastic-tests.xml

coverage:
	$(PYTHON) tools/generate_coverage.py --json-output artifacts/inventory.json

lab-up:
	docker compose up -d --wait

lab-down:
	docker compose down
