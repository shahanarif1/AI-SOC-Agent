# Directory Structure

This document describes the organized structure of the Wazuh MCP Server repository.

## Root Directory
```
Wazuh-MCP-Server/
├── README.md                    # Main project documentation
├── LICENSE                      # MIT License
├── CHANGELOG.md                 # Version history and changes
├── pyproject.toml              # Python project configuration
├── requirements*.txt           # Python dependencies
└── .github/                    # GitHub-specific files
    └── workflows/              # CI/CD workflows (future)
```

## Source Code
```
src/
└── wazuh_mcp_server/           # Main application package
    ├── __init__.py
    ├── __version__.py          # Version information
    ├── config.py               # Configuration management
    ├── main.py                 # MCP server entry point
    ├── api/                    # Wazuh API clients
    │   ├── wazuh_client.py
    │   ├── wazuh_client_manager.py
    │   ├── wazuh_field_mappings.py
    │   └── wazuh_indexer_client.py
    ├── analyzers/              # Security analysis engines
    │   ├── compliance_analyzer.py
    │   └── security_analyzer.py
    ├── prompt_enhancement/     # Phase 5 enhancement system
    │   ├── adapters.py         # Adaptive formatting
    │   ├── cache.py            # Context caching
    │   ├── context_aggregator.py # Main aggregation engine
    │   ├── pipelines.py        # Context pipelines
    │   └── updates.py          # Real-time updates
    ├── scripts/                # Internal utility scripts
    │   ├── connection_validator.py
    │   └── test_connection.py
    └── utils/                  # Utility modules
        ├── error_recovery.py
        ├── exceptions.py
        ├── logging.py
        ├── platform_utils.py
        ├── production_error_handler.py
        ├── rate_limiter.py
        ├── ssl_config.py
        └── validation.py
```

## Testing
```
tests/                          # Test suite
├── conftest.py                 # Pytest configuration
├── fixtures/                   # Test data and fixtures
│   └── mock_data.py
├── test_*.py                   # Individual test modules
└── test_phase5_*.py            # Phase 5 specific tests
```

## Documentation
```
docs/                           # All documentation
├── DIRECTORY_STRUCTURE.md      # This file
├── user-guides/                # User-facing documentation
│   ├── claude-desktop-setup.md # Setup instructions
│   ├── unix-troubleshooting.md # Unix/Linux troubleshooting
│   └── windows-troubleshooting.md # Windows troubleshooting
├── technical/                  # Technical documentation
│   ├── COMPREHENSIVE_AUDIT_REPORT.md
│   ├── PHASE_5_PROMPT_ENHANCEMENT_DETAILED_PLAN.md
│   └── WRAPPER_SCRIPT_DOCUMENTATION.md
└── development/                # Development documentation
    └── CONTRIBUTING.md         # Contribution guidelines
```

## Scripts and Utilities
```
scripts/                        # Installation and utility scripts
├── install.py                  # Main installation script
├── install-windows.bat         # Windows batch installer
├── mcp_wrapper.sh             # Unix wrapper script
├── test_wrapper.sh            # Testing wrapper
└── validate_setup.py          # Setup validation
```

## Examples (Future)
```
examples/                       # Usage examples
├── basic_usage.py             # Basic MCP usage examples
├── advanced_queries.py        # Advanced query examples
└── configuration_examples/     # Configuration examples
    ├── basic_config.env
    ├── production_config.env
    └── development_config.env
```

## File Naming Conventions

### Python Files
- **Modules**: `snake_case.py`
- **Classes**: `PascalCase` within files
- **Functions**: `snake_case`
- **Constants**: `UPPER_SNAKE_CASE`

### Documentation Files
- **User guides**: `kebab-case.md` in `docs/user-guides/`
- **Technical docs**: `UPPER_SNAKE_CASE.md` in `docs/technical/`
- **Development docs**: `UPPER_SNAKE_CASE.md` in `docs/development/`

### Test Files
- **Pattern**: `test_*.py` in `tests/` directory
- **Phase-specific**: `test_phase5_*.py` for Phase 5 components
- **Integration**: `test_*_integration.py` for integration tests

### Configuration Files
- **Python config**: `pyproject.toml`
- **Requirements**: `requirements*.txt`
- **Environment**: `.env` (not tracked)

## Best Practices

### Directory Organization
1. **Separation of Concerns**: Each directory has a specific purpose
2. **Logical Grouping**: Related files are grouped together
3. **Clear Naming**: Directory names clearly indicate their contents
4. **Documentation**: Each major directory has explanatory documentation

### File Organization
1. **Imports**: Organized with standard library, third-party, then local imports
2. **Documentation**: Every module, class, and function has docstrings
3. **Type Hints**: All functions use proper type annotations
4. **Error Handling**: Comprehensive error handling throughout

### Testing Organization
1. **Test Structure**: Tests mirror the source code structure
2. **Fixtures**: Reusable test data in dedicated fixtures directory
3. **Coverage**: Comprehensive test coverage for all components
4. **Isolation**: Tests are independent and can run in any order

This structure ensures maintainability, scalability, and ease of navigation for both users and developers.