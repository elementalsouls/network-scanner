.PHONY: install install-dev test lint format run-web docker-build docker-up clean

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	pytest tests/ -v --cov=scanner --cov-report=term-missing

lint:
	flake8 scanner/ tests/ --max-line-length=120 --ignore=E501,W503

format:
	black scanner/ tests/

run-web:
	python -m scanner web --port 8080

docker-build:
	docker build -t network-scanner .

docker-up:
	docker-compose up -d

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf dist/ build/ *.egg-info/ .pytest_cache/ htmlcov/ .coverage
