.PHONY: install lint test run pack fmt

install:
	python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

fmt:
	ruff check --select I --fix . || true
	ruff check --fix . || true

lint:
	ruff check .

test:
	pytest -q --cov=src --cov-report=term-missing

run:
	uvicorn src.signet.app:app --reload --port 8080

pack:
	python tools/pch_client_demo.py --url http://localhost:8080/protected
