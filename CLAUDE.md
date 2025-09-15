# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **AI-SOC-Agent** - a production-grade Wazuh MCP (Model Context Protocol) Server that integrates Wazuh SIEM with Claude Desktop for AI-powered security operations. The codebase consists of both a comprehensive MCP server (`src/wazuh_mcp_server/`) and a Streamlit client application (`src/wazuh_client.py`).

## Key Commands

### Development Setup
```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup development environment
python scripts/install.py
python scripts/validate_setup.py
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_specific_file.py

# Run tests with asyncio support
pytest -v tests/
```

### Code Quality
```bash
# Format code with Black
black src/ tests/

# Lint with Ruff
ruff check src/ tests/

# Type checking with MyPy
mypy src/

# Run all quality checks
black . && ruff check . && mypy src/
```

### Running the Application

#### MCP Server (for Claude Desktop integration)
```bash
# Direct execution
python -m wazuh_mcp_server

# Using entry point (after installation)
wazuh-mcp-server

# Test connection
wazuh-mcp-test
```

#### Streamlit Client Application
```bash
# Run the Streamlit client
streamlit run src/wazuh_client.py
```

## Architecture Overview

### Core Components

1. **MCP Server (`src/wazuh_mcp_server/`)**
   - **API Layer**: Wazuh API client management with dual API support (Manager + Indexer)
     - `api/wazuh_client.py` - Core Wazuh Manager API client
     - `api/wazuh_indexer_client.py` - Elasticsearch/OpenSearch client for Wazuh 4.8+
     - `api/wazuh_client_manager.py` - Unified client management
     - `api/wazuh_field_mappings.py` - Cross-version compatibility

   - **Security Analysis**: Advanced threat detection and compliance checking
     - `analyzers/security_analyzer.py` - Threat analysis and risk assessment
     - `analyzers/compliance_analyzer.py` - Multi-framework compliance (PCI DSS, HIPAA, GDPR, NIST, ISO27001)

   - **Prompt Enhancement System**: AI-powered context aggregation
     - `prompt_enhancement/context_aggregator.py` - Intelligent context gathering
     - `prompt_enhancement/adapters.py` - Dynamic response formatting
     - `prompt_enhancement/pipelines.py` - Specialized analysis pipelines
     - `prompt_enhancement/cache.py` - LRU caching with TTL

   - **MCP Tools**: 23+ security analysis tools in `tools/` directory
   - **Configuration**: Comprehensive settings management in `config.py`
   - **Entry Point**: `main.py` - MCP server initialization

2. **Streamlit Client (`src/wazuh_client.py`)**
   - Interactive web interface for Wazuh MCP server communication
   - Integrates with Azure OpenAI (GPT-4) for AI analysis
   - Uses MCP stdio client for server communication

### Configuration System

The project uses extensive environment-based configuration:

- **Core Settings**: Wazuh host, credentials, SSL configuration
- **Performance**: Connection pooling, timeouts, cache settings
- **Security**: SSL/TLS options, certificate management, API keys
- **Features**: 50+ environment variables for fine-tuned control

Key configuration files:
- `.env.example` - Comprehensive configuration template (270+ lines)
- `pyproject.toml` - Build configuration and tool settings
- Environment variables take precedence over defaults

### Testing Strategy

- **27 test files** providing comprehensive coverage
- **Unit tests**: Component-specific validation
- **Integration tests**: End-to-end MCP tool testing
- **Async testing**: Full pytest-asyncio support
- **Production stability**: Load and performance tests

Test structure follows the source layout with dedicated tests for each major component.

## Development Practices

### Code Style
- **Black** formatter (88-char line length)
- **Ruff** linting with comprehensive rule set
- **MyPy** strict type checking (except tests)
- Python 3.9+ compatibility

### Package Structure
```
src/wazuh_mcp_server/
├── analyzers/          # Security and compliance analysis
├── api/                # Wazuh API clients and management
├── prompt_enhancement/ # AI context aggregation system
├── scripts/            # Utility scripts
├── tools/              # MCP tool implementations
├── utils/              # Common utilities
├── config.py           # Configuration management
└── main.py             # MCP server entry point
```

### Key Dependencies
- **MCP**: Core Model Context Protocol framework (>=1.10.1)
- **aiohttp**: Async HTTP client for Wazuh API communication
- **pydantic**: Data validation with v1.10+ and v2.x compatibility
- **streamlit**: Web interface (client application)
- **openai**: Azure OpenAI integration (client application)

## Environment Setup

1. Copy `.env.example` to `.env` and configure Wazuh credentials
2. Set required variables: `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASS`
3. Optional: Configure external threat intelligence APIs (VirusTotal, Shodan, AbuseIPDB)
4. For Streamlit client: Set `OPENAI_API_KEY` and `END_POINT` for Azure OpenAI

## Production Considerations

- **SSL Configuration**: Defaults to secure settings with self-signed certificate support
- **Performance**: Built-in caching, connection pooling, and memory management
- **Cross-Platform**: Native support for Windows, macOS, and Linux distributions
- **Enterprise Ready**: Comprehensive error handling, logging, and monitoring capabilities