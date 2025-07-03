# Makefile for Wazuh MCP Server - Cross-Platform Production Build
.PHONY: help install install-dev clean test lint format security build package deploy health-check docs

# Cross-platform variables
ifeq ($(OS),Windows_NT)
    PYTHON := python
    PIP := pip
    RM := del /Q
    RMDIR := rmdir /S /Q
    NULLDEV := NUL
    PATHSEP := ;
else
    PYTHON := python3
    PIP := pip3
    RM := rm -f
    RMDIR := rm -rf
    NULLDEV := /dev/null
    PATHSEP := :
endif

PACKAGE_NAME := wazuh-mcp-server
VERSION := $(shell $(PYTHON) -c "from src.__version__ import __version__; print(__version__)" 2>$(NULLDEV) || echo "unknown")

help: ## Show this help message
	@echo "🛡️  Wazuh MCP Server DXT - Production Build System"
	@echo "=================================================="
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install production dependencies
	@echo "📦 Installing production dependencies..."
	$(PIP) install -r requirements.txt
	$(PIP) install -e .
	@echo "✅ Installation complete! Use 'wazuh-mcp-server' to start"

install-dev: ## Install development dependencies
	@echo "🔧 Installing development dependencies..."
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .
	@echo "✅ Development environment ready!"

clean: ## Clean build artifacts and cache
	@echo "🧹 Cleaning build artifacts..."
	$(RMDIR) build 2>$(NULLDEV) || true
	$(RMDIR) dist 2>$(NULLDEV) || true
	$(RMDIR) *.egg-info 2>$(NULLDEV) || true
	$(RMDIR) .pytest_cache 2>$(NULLDEV) || true
	$(RMDIR) htmlcov 2>$(NULLDEV) || true
	$(RMDIR) .mypy_cache 2>$(NULLDEV) || true
	$(RM) .coverage 2>$(NULLDEV) || true
ifeq ($(OS),Windows_NT)
	@for /r %%i in (__pycache__) do @if exist "%%i" $(RMDIR) "%%i" 2>$(NULLDEV)
	@for /r %%i in (*.pyc) do @if exist "%%i" $(RM) "%%i" 2>$(NULLDEV)
	@for /r %%i in (*.pyo) do @if exist "%%i" $(RM) "%%i" 2>$(NULLDEV)
else
	find . -type d -name __pycache__ -exec $(RMDIR) {} + 2>$(NULLDEV) || true
	find . -type f -name "*.pyc" -delete 2>$(NULLDEV) || true
	find . -type f -name "*.pyo" -delete 2>$(NULLDEV) || true
endif

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

dev-setup: install-dev fix-permissions ## Set up development environment
	@echo "🚀 Setting up development environment..."
	@make validate-env
	@echo "✅ Development environment ready!"
	@echo "💡 Quick commands:"
	@echo "   make run-server    - Start the server"
	@echo "   make run-test      - Test connection"
	@echo "   make test          - Run test suite"

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
ifeq ($(OS),Windows_NT)
	@echo "File watching not implemented for Windows. Run 'make test' manually."
else
	find src tests -name "*.py" | entr -c make test-quick
endif

# Cross-platform testing and validation
test-connection: install ## Test Wazuh connection
	@echo "🔍 Testing Wazuh connection..."
	$(PYTHON) -m scripts.test_connection

test-scripts: install ## Test all scripts work correctly
	@echo "🧪 Testing script execution..."
	$(PYTHON) scripts/run.py install
	$(PYTHON) scripts/run.py env-check
	@echo "✅ All scripts working!"

run-server: install ## Run the MCP server
	@echo "🚀 Starting Wazuh MCP Server..."
	wazuh-mcp-server

run-test: install ## Run connection test
	@echo "🔍 Running connection test..."
	wazuh-mcp-test

# Environment validation
validate-env: ## Validate Python environment
	@echo "🔍 Validating environment..."
	$(PYTHON) -c "from src.utils.import_helper import validate_environment, check_dependencies, get_python_info; get_python_info(); validate_environment(); check_dependencies()"

check-ssl: install ## Check SSL/TLS connectivity and configuration
	@echo "🔒 Checking SSL/TLS configuration..."
	$(PYTHON) scripts/check_ssl.py

test-ssl: check-ssl ## Alias for check-ssl
	@echo "✅ SSL test completed"

setup-ssl: install ## Smart SSL configuration for maximum compatibility
	@echo "🔒 Running smart SSL setup..."
	$(PYTHON) scripts/setup_ssl.py

fix-ssl: ## Attempt to fix common SSL issues
	@echo "🔧 Attempting to fix SSL issues..."
	$(PYTHON) -c "from src.utils.ssl_helper import fix_pip_ssl_issues; fixes = fix_pip_ssl_issues(); print('Fixes applied:', fixes)"
	$(PIP) install --upgrade certifi requests urllib3

# Quick fixes for common issues
fix-imports: ## Fix import issues by reinstalling package
	@echo "🔧 Fixing import issues..."
	$(PIP) uninstall -y $(PACKAGE_NAME) 2>$(NULLDEV) || true
	$(PIP) install -e .
	@echo "✅ Import fix complete!"

fix-permissions: ## Fix file permissions (Unix only)
ifeq ($(OS),Windows_NT)
	@echo "Permission fixing not needed on Windows"
else
	@echo "🔧 Fixing file permissions..."
	chmod +x scripts/*.py
	chmod +x src/*.py
	@echo "✅ Permissions fixed!"
endif