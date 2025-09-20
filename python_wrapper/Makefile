# WAF + Reverse Proxy Python Wrapper Makefile
# Provides easy installation, testing, and development commands

.PHONY: help install install-dev test lint format clean build publish demo docs

# Default target
help:
	@echo "WAF + Reverse Proxy Python Wrapper"
	@echo "==================================="
	@echo ""
	@echo "Available commands:"
	@echo "  install      Install the package"
	@echo "  install-dev  Install in development mode with all dependencies"
	@echo "  test         Run tests"
	@echo "  lint         Run code linting"
	@echo "  format       Format code with black"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build distribution packages"
	@echo "  publish      Publish to PyPI (requires credentials)"
	@echo "  demo         Run the demo script"
	@echo "  docs         Generate documentation"
	@echo "  venv         Create virtual environment"
	@echo ""
	@echo "Development workflow:"
	@echo "  make venv && source venv/bin/activate"
	@echo "  make install-dev"
	@echo "  make test"
	@echo "  make demo"

# Virtual environment
venv:
	@echo "Creating virtual environment..."
	python3 -m venv venv
	@echo "Virtual environment created. Activate with:"
	@echo "  source venv/bin/activate  (Linux/Mac)"
	@echo "  venv\\Scripts\\activate     (Windows)"

# Installation targets
install:
	@echo "Installing WAF Proxy Python Wrapper..."
	pip install .

install-dev:
	@echo "Installing WAF Proxy Python Wrapper in development mode..."
	pip install -e .[dev,all]
	@echo "Installing additional development tools..."
	pip install pre-commit sphinx sphinx-autodoc-typehints
	@echo "Setting up pre-commit hooks..."
	pre-commit install

install-minimal:
	@echo "Installing minimal dependencies..."
	pip install -e .

# Testing
test:
	@echo "Running tests..."
	pytest tests/ -v --cov=waf_proxy --cov-report=term-missing

test-quick:
	@echo "Running quick tests..."
	pytest tests/ -x --tb=short

test-integration:
	@echo "Running integration tests..."
	pytest tests/integration/ -v

# Code quality
lint:
	@echo "Running linting..."
	flake8 waf_proxy/ tests/
	mypy waf_proxy/

lint-fix:
	@echo "Auto-fixing linting issues..."
	autopep8 --in-place --recursive waf_proxy/ tests/

format:
	@echo "Formatting code with black..."
	black waf_proxy/ tests/ examples/

format-check:
	@echo "Checking code formatting..."
	black --check waf_proxy/ tests/ examples/

# Build and distribution
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	@echo "Building distribution packages..."
	python setup.py sdist bdist_wheel

publish: build
	@echo "Publishing to PyPI..."
	twine check dist/*
	twine upload dist/*

publish-test: build
	@echo "Publishing to Test PyPI..."
	twine check dist/*
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

# Documentation
docs:
	@echo "Generating documentation..."
	cd docs && make html
	@echo "Documentation generated in docs/_build/html/"

docs-serve:
	@echo "Starting documentation server..."
	cd docs/_build/html && python -m http.server 8000

# Demo and examples
demo:
	@echo "Running comprehensive demo..."
	python examples/demo.py

demo-config:
	@echo "Running configuration demo..."
	python -c "from examples.demo import demo_configuration_management; demo_configuration_management()"

demo-health:
	@echo "Running health monitoring demo..."
	python -c "from examples.demo import demo_health_monitoring; demo_health_monitoring()"

# CLI testing
cli-test:
	@echo "Testing CLI commands..."
	waf-proxy --help
	waf-proxy config --help
	waf-proxy health --help

# Development utilities
check-deps:
	@echo "Checking dependencies..."
	pip check

update-deps:
	@echo "Updating dependencies..."
	pip install --upgrade pip setuptools wheel
	pip install --upgrade -r requirements.txt

freeze-deps:
	@echo "Freezing dependencies..."
	pip freeze > requirements-frozen.txt

# Security checks
security-check:
	@echo "Running security checks..."
	safety check
	bandit -r waf_proxy/

# Performance testing
perf-test:
	@echo "Running performance tests..."
	python -m pytest tests/performance/ -v

# Integration with the Rust binary
rust-build:
	@echo "Building Rust binary..."
	cd .. && cargo build --release

rust-test:
	@echo "Testing with Rust binary..."
	cd .. && cargo test

full-test: rust-build test
	@echo "Running full test suite with Rust binary..."
	python tests/integration/test_with_binary.py

# Docker support
docker-build:
	@echo "Building Docker image..."
	docker build -t waf-proxy-python .

docker-run:
	@echo "Running in Docker..."
	docker run -it --rm -v $(PWD):/workspace waf-proxy-python

# Kubernetes support
k8s-deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f ../deployment/kubernetes/

# Development environment
dev-setup: venv install-dev
	@echo "Development environment setup complete!"
	@echo "Activate the virtual environment:"
	@echo "  source venv/bin/activate"

dev-reset: clean
	@echo "Resetting development environment..."
	rm -rf venv/
	make dev-setup

# Release workflow
pre-release: clean format lint test docs build
	@echo "Pre-release checks complete!"

release: pre-release publish
	@echo "Release complete!"

# Monitoring and maintenance
check-health:
	@echo "Checking package health..."
	pip check
	python -c "import waf_proxy; print('✅ Package imports successfully')"

benchmark:
	@echo "Running benchmarks..."
	python benchmarks/client_benchmark.py

# CI/CD helpers
ci-test:
	@echo "Running CI tests..."
	pytest tests/ --junitxml=test-results.xml --cov=waf_proxy --cov-report=xml

ci-publish:
	@echo "CI publish (requires CI environment)..."
	python -m build
	python -m twine upload dist/* --non-interactive

# Examples and tutorials
example-basic:
	@echo "Running basic usage example..."
	python examples/basic_usage.py

example-async:
	@echo "Running async example..."
	python examples/async_usage.py

example-flask:
	@echo "Running Flask integration example..."
	python examples/flask_integration.py

example-fastapi:
	@echo "Running FastAPI integration example..."
	python examples/fastapi_integration.py

# Utilities
version:
	@echo "Package version:"
	@python -c "from waf_proxy import __version__; print(__version__)"

info:
	@echo "Package information:"
	@echo "Name: waf-proxy-wrapper"
	@python -c "from waf_proxy import __version__, __author__; print(f'Version: {__version__}'); print(f'Author: {__author__}')"
	@echo "Dependencies:"
	@pip list | grep -E "(requests|aiohttp|psutil|PyYAML)"

status:
	@echo "Development status:"
	@echo "Git status:"
	@git status --porcelain || echo "Not in a git repository"
	@echo "Virtual environment:"
	@which python
	@python --version
	@echo "Installed packages:"
	@pip list | wc -l | xargs echo "Total packages:"

# Help for specific topics
help-install:
	@echo "Installation Help"
	@echo "=================="
	@echo ""
	@echo "Basic installation:"
	@echo "  pip install ."
	@echo ""
	@echo "Development installation:"
	@echo "  make install-dev"
	@echo ""
	@echo "With specific features:"
	@echo "  pip install .[cli]      # CLI enhancements"
	@echo "  pip install .[monitoring] # Monitoring features"
	@echo "  pip install .[all]     # All optional features"

help-development:
	@echo "Development Help"
	@echo "================="
	@echo ""
	@echo "Setup development environment:"
	@echo "  make dev-setup"
	@echo ""
	@echo "Development workflow:"
	@echo "  1. make format        # Format code"
	@echo "  2. make lint          # Check code quality"
	@echo "  3. make test          # Run tests"
	@echo "  4. make demo          # Test functionality"
	@echo ""
	@echo "Before committing:"
	@echo "  make pre-release"

help-testing:
	@echo "Testing Help"
	@echo "============="
	@echo ""
	@echo "Run all tests:"
	@echo "  make test"
	@echo ""
	@echo "Quick tests:"
	@echo "  make test-quick"
	@echo ""
	@echo "Integration tests:"
	@echo "  make test-integration"
	@echo ""
	@echo "Performance tests:"
	@echo "  make perf-test"

help-cli:
	@echo "CLI Help"
	@echo "========"
	@echo ""
	@echo "After installation, use:"
	@echo "  waf-proxy --help"
	@echo ""
	@echo "Common commands:"
	@echo "  waf-proxy start --config config.yaml"
	@echo "  waf-proxy status"
	@echo "  waf-proxy health --full"
	@echo "  waf-proxy stats waf"
	@echo "  waf-proxy config validate"
