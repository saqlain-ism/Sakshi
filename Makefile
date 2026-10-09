.PHONY: install run distributed test java-test bench vectors lint

install:      ## install with all extras
	pip install -e ".[dev]"

run:          ## whole network in one process: http://localhost:8000
	uvicorn sakshi_network.app:create_app --factory --port 8000

distributed:  ## nine separate services, no Docker needed
	./scripts/run_distributed.sh

test:
	pytest -q

java-test:
	cd java && mvn -B -q test

bench:
	python benchmarks/perf_benchmark.py --json benchmarks/perf_results.json
	python benchmarks/fraud_benchmark.py --json benchmarks/fraud_results.json

vectors:      ## regenerate cross-language test vectors
	python scripts/make_test_vectors.py

lint:
	ruff check src tests benchmarks scripts
