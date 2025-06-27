# Makefile for Wazuh MCP Server DXT Production Build
.PHONY: help install install-dev clean test lint format security build package deploy health-check docs

# Variables
PYTHON := python3
PIP := pip3
PACKAGE_NAME := wazuh-mcp-server
VERSION := $(shell python3 -c "from src.__version__ import __version__; print(__version__)")

help: ## Show this help message
	@echo "🛡️  Wazuh MCP Server DXT - Production Build System"
	@echo "=================================================="
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install production dependencies
	@echo "📦 Installing production dependencies..."
	$(PIP) install -r requirements.txt

install-dev: ## Install development dependencies
	@echo "🔧 Installing development dependencies..."
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

clean: ## Clean build artifacts and cache
	@echo "🧹 Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.dxt" -delete

test: ## Run test suite
	@echo "🧪 Running test suite..."
	$(PYTHON) -m pytest tests/ -v --cov=src --cov-report=html --cov-report=term

test-integration: ## Run integration tests
	@echo "🔗 Running integration tests..."
	$(PYTHON) -m pytest tests/test_dxt_integration.py -v

lint: ## Run code linting
	@echo "🔍 Running code linting..."
	$(PYTHON) -m flake8 src/ tests/
	$(PYTHON) -m mypy src/ --ignore-missing-imports

format: ## Format code with black and isort
	@echo "✨ Formatting code..."
	$(PYTHON) -m black src/ tests/
	$(PYTHON) -m isort src/ tests/

format-check: ## Check code formatting
	@echo "🔍 Checking code formatting..."
	$(PYTHON) -m black --check src/ tests/
	$(PYTHON) -m isort --check-only src/ tests/

security: ## Run security checks
	@echo "🛡️ Running security checks..."
	$(PYTHON) -m bandit -r src/ -f json -o bandit-report.json
	$(PYTHON) -m bandit -r src/
	$(PYTHON) -m safety check
	$(PYTHON) -m pip_audit

performance: ## Run performance benchmarks
	@echo "⚡ Running performance benchmarks..."
	$(PYTHON) -m pytest tests/ --benchmark-only

build: clean lint security ## Build the package
	@echo "🏗️ Building package..."
	$(PYTHON) -m build

validate-manifest: ## Validate DXT manifest
	@echo "📋 Validating DXT manifest..."
	$(PYTHON) -c "import json; json.load(open('manifest.json')); print('✅ Manifest is valid JSON')"
	$(PYTHON) scripts/package_dxt.py --validate-only

package: build validate-manifest ## Create DXT package
	@echo "📦 Creating DXT package..."
	$(PYTHON) scripts/package_dxt.py
	@echo "✅ DXT package created: $(PACKAGE_NAME)-$(VERSION).dxt"

package-test: ## Create test DXT package
	@echo "🧪 Creating test DXT package..."
	$(PYTHON) scripts/package_dxt.py --test-mode

health-check: ## Run health checks
	@echo "🩺 Running health checks..."
	$(PYTHON) src/health_check.py

docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	cd docs && $(PYTHON) -m sphinx -b html . _build/html

check-version: ## Check version consistency
	@echo "🔢 Checking version consistency..."
	@echo "Setup.py version: $(shell grep version setup.py | cut -d'"' -f2)"
	@echo "Manifest version: $(shell python3 -c "import json; print(json.load(open('manifest.json'))['version'])")"
	@echo "Package.json version: $(shell python3 -c "import json; print(json.load(open('package.json'))['version'])")"

dev-setup: install-dev ## Set up development environment
	@echo "🚀 Setting up development environment..."
	@echo "✅ Development environment ready!"
	@echo "Run 'make test' to verify everything works"

ci: clean format-check lint security test ## Run full CI pipeline
	@echo "🚀 Running full CI pipeline..."
	@echo "✅ CI pipeline completed successfully!"

release: ci build package ## Build release
	@echo "🎉 Building release $(VERSION)..."
	@echo "📦 Package: $(PACKAGE_NAME)-$(VERSION).dxt"
	@echo "✅ Release ready for deployment!"

deploy-check: ## Check deployment readiness
	@echo "🔍 Checking deployment readiness..."
	@echo "Version: $(VERSION)"
	@test -f "$(PACKAGE_NAME)-$(VERSION).dxt" || (echo "❌ DXT package not found" && exit 1)
	@echo "✅ Deployment ready!"

status: ## Show project status
	@echo "📊 Project Status"
	@echo "================"
	@echo "Version: $(VERSION)"
	@echo "Python: $(shell $(PYTHON) --version)"
	@echo "Package exists: $(shell test -f '$(PACKAGE_NAME)-$(VERSION).dxt' && echo '✅ Yes' || echo '❌ No')"
	@echo "Dependencies: $(shell $(PIP) check > /dev/null 2>&1 && echo '✅ OK' || echo '❌ Issues found')"

# Development shortcuts
dev: dev-setup ## Alias for dev-setup
test-quick: ## Run quick tests (no coverage)
	@echo "⚡ Running quick tests..."
	$(PYTHON) -m pytest tests/ -x --no-cov

watch-tests: ## Watch files and run tests on changes
	@echo "👀 Watching for changes..."
	find src tests -name "*.py" | entr -c make test-quick