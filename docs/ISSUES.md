# Known Issues and Potential Breaking Changes

**Last Updated**: July 11, 2025  
**Version**: v2.0.0 (Upcoming) vs v1.0.0 (Stable)

This document tracks known issues, potential breaking changes, and areas of concern in the current implementation.

---

## 🚨 **Critical Issues**

### **1. ❌ Documentation Path References**
**Severity**: HIGH  
**Status**: NEEDS FIX  
**Description**: Several documentation files contain outdated path references after repository restructuring.

**Affected Files**:
- `docs/development/CONTRIBUTING.md` - References `python3 install.py` instead of `python3 scripts/install.py`
- `docs/user-guides/unix-troubleshooting.md` - Multiple references to `mcp_wrapper.sh` instead of `scripts/mcp_wrapper.sh`

**Impact**: Users following documentation will encounter file not found errors.

**Fix Required**:
```bash
# Update all documentation to use correct paths
sed -i 's|install.py|scripts/install.py|g' docs/**/*.md
sed -i 's|mcp_wrapper.sh|scripts/mcp_wrapper.sh|g' docs/**/*.md
```

---

## ⚠️ **Breaking Changes from v1.0.0**

### **2. Script Locations Changed**
**Severity**: MEDIUM  
**Status**: DOCUMENTED BUT MAY BREAK EXISTING SETUPS  
**Description**: All scripts moved from root to `scripts/` directory.

**Changes**:
- `install.py` → `scripts/install.py`
- `mcp_wrapper.sh` → `scripts/mcp_wrapper.sh`
- `validate_setup.py` → `scripts/validate_setup.py`

**Impact**: 
- Existing Claude Desktop configurations will break
- Automated deployment scripts will fail
- User documentation references are incorrect

**Migration Required**:
```json
// Update claude_desktop_config.json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh",  // Add 'scripts/'
      "args": ["--stdio"]
    }
  }
}
```

---

## 🔧 **Configuration Issues**

### **3. Feature Flags Default to False**
**Severity**: LOW  
**Status**: BY DESIGN BUT MAY CONFUSE USERS  
**Description**: All Phase 5 enhancement features are disabled by default.

**Affected Features**:
- `enable_prompt_enhancement` = False
- `enable_context_aggregation` = False
- `enable_adaptive_responses` = False
- `enable_realtime_updates` = False

**Impact**: Users won't see new features without explicit configuration.

**User Action Required**:
```env
# Add to .env file to enable new features
ENABLE_PROMPT_ENHANCEMENT=true
ENABLE_CONTEXT_AGGREGATION=true
ENABLE_ADAPTIVE_RESPONSES=true
ENABLE_REALTIME_UPDATES=true
```

---

## 🐛 **Potential Runtime Issues**

### **4. Hardcoded Unix Paths in Code**
**Severity**: MEDIUM  
**Status**: WINDOWS COMPATIBILITY ISSUE  
**Description**: Several hardcoded Unix paths exist in the codebase.

**Found in**:
- `main.py:14701` - `/var/ossec/logs/` paths
- `main.py:15184-15190` - Multiple `/var/ossec/logs/` references
- `platform_utils.py:121` - `/var/log` path

**Impact**: May cause errors on Windows systems when these code paths are executed.

**Recommendation**: Use platform-agnostic path handling:
```python
from pathlib import Path
log_path = Path("/var/ossec/logs") if platform.system() != "Windows" else Path("C:/Program Files/ossec/logs")
```

### **5. Large Memory Footprint**
**Severity**: MEDIUM  
**Status**: PERFORMANCE CONCERN  
**Description**: Phase 5 enhancement system adds significant memory overhead.

**Concerns**:
- Context caching can consume significant memory
- Real-time monitoring keeps contexts in memory
- No explicit memory limits configured

**Recommendation**: Add memory management configuration:
```env
MAX_CACHE_MEMORY_MB=500
MAX_CONTEXT_COUNT=100
CACHE_CLEANUP_AGGRESSIVE=true
```

---

## 📦 **Dependency Issues**

### **6. Missing Optional Dependencies**
**Severity**: LOW  
**Status**: HANDLED BUT MAY CAUSE CONFUSION  
**Description**: Some imports are handled with try/except but may cause reduced functionality.

**Potential Issues**:
- External API integrations (VirusTotal, Shodan) fail silently
- Some enhanced features degrade without clear user notification

**Recommendation**: Add optional dependency checking:
```python
# Add to startup
missing_features = []
try:
    import virustotal
except ImportError:
    missing_features.append("VirusTotal integration")
    
if missing_features:
    logger.warning(f"Optional features unavailable: {', '.join(missing_features)}")
```

---

## 🔍 **Code Quality Issues**

### **7. Inconsistent Error Handling**
**Severity**: LOW  
**Status**: MINOR INCONSISTENCY  
**Description**: Some Phase 5 components use different error handling patterns.

**Examples**:
- Some functions return None on error
- Others raise exceptions
- Inconsistent logging levels

**Recommendation**: Standardize error handling across all components.

### **8. Large Single File (main.py)**
**Severity**: MEDIUM  
**Status**: TECHNICAL DEBT  
**Description**: `main.py` has grown to 18,475 lines (from 2,093 in v1.0.0).

**Issues**:
- Difficult to maintain and navigate
- Slow IDE performance
- Higher chance of merge conflicts

**Recommendation**: Refactor into multiple modules:
```
src/wazuh_mcp_server/
├── tools/
│   ├── alerts.py
│   ├── agents.py
│   ├── compliance.py
│   └── ...
└── main.py  # Just the server setup
```

---

## 🚦 **Testing Gaps**

### **9. Windows-Specific Testing**
**Severity**: MEDIUM  
**Status**: LIMITED COVERAGE  
**Description**: Most tests assume Unix-like environment.

**Missing**:
- Windows path handling tests
- Windows service integration tests
- PowerShell script testing

### **10. Performance Testing**
**Severity**: LOW  
**Status**: NO LOAD TESTING  
**Description**: No performance benchmarks or load tests exist.

**Needed**:
- Memory usage under load
- Response time with large datasets
- Concurrent request handling

---

## 📝 **Documentation Issues**

### **11. Incomplete Migration Guide**
**Severity**: LOW  
**Status**: NEEDS ENHANCEMENT  
**Description**: Migration from v1.0.0 needs more detailed steps.

**Missing**:
- Script path migration automation
- Feature comparison table
- Rollback procedures

### **12. API Changes Not Documented**
**Severity**: MEDIUM  
**Status**: MISSING DOCUMENTATION  
**Description**: Internal API changes between versions not documented.

**Needed**:
- API changelog
- Deprecation notices
- Integration update guide

---

## 🔐 **Security Considerations**

### **13. Feature Flag Security**
**Severity**: LOW  
**Status**: MINOR CONCERN  
**Description**: Feature flags are read from environment without validation.

**Risk**: Malformed feature flag values could cause unexpected behavior.

**Recommendation**: Add validation:
```python
def validate_feature_flag(value: str) -> bool:
    return value.lower() in ('true', '1', 'yes', 'on')
```

---

## 📊 **Summary**

### **Critical Issues Requiring Immediate Fix**:
1. Documentation path references (HIGH)
2. Script location breaking changes (MEDIUM)

### **Should Fix Before Release**:
1. Windows compatibility for hardcoded paths
2. Memory management configuration
3. Error handling standardization

### **Can Be Addressed Post-Release**:
1. Code refactoring (main.py size)
2. Performance testing
3. Enhanced documentation

### **Total Issues by Severity**:
- 🔴 **Critical**: 1
- 🟠 **High**: 1
- 🟡 **Medium**: 7
- 🟢 **Low**: 4

---

## 🛠️ **Recommended Actions**

1. **Before Release**:
   ```bash
   # Fix documentation paths
   find docs -name "*.md" -exec sed -i 's|install.py|scripts/install.py|g' {} \;
   find docs -name "*.md" -exec sed -i 's|mcp_wrapper.sh|scripts/mcp_wrapper.sh|g' {} \;
   
   # Add migration script
   echo "#!/bin/bash
   # Update Claude Desktop config
   sed -i 's|/mcp_wrapper.sh|/scripts/mcp_wrapper.sh|g' ~/Library/Application\\ Support/Claude/claude_desktop_config.json
   " > scripts/migrate_v1_to_v2.sh
   ```

2. **Release Notes Must Include**:
   - Script location changes
   - Feature flag configuration
   - Memory requirements
   - Migration steps

3. **Post-Release Priorities**:
   - Refactor main.py
   - Add performance tests
   - Enhance Windows support

---

**Note**: Most issues are minor and don't affect core functionality. The implementation is stable and production-ready with these known limitations.