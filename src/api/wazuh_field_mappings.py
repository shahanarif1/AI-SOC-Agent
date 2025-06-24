"""Production-grade field mappings for Wazuh API compatibility across versions."""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum


class WazuhVersion(Enum):
    """Supported Wazuh versions."""
    V4_7_X = "4.7.x"
    V4_8_X = "4.8.x"
    V4_9_X = "4.9.x"
    UNKNOWN = "unknown"


@dataclass
class FieldMapping:
    """Field mapping configuration for different Wazuh versions."""
    server_field: str
    indexer_field: str
    field_type: str
    required: bool = False
    default_value: Any = None
    transformation: Optional[str] = None


class WazuhFieldMapper:
    """Production-grade field mapper for Wazuh API compatibility."""
    
    # Alert field mappings across versions
    ALERT_FIELD_MAPPINGS = {
        # Timestamp fields
        "timestamp": FieldMapping("timestamp", "@timestamp", "datetime", True),
        
        # Rule fields
        "rule_id": FieldMapping("rule.id", "rule.id", "integer", True),
        "rule_level": FieldMapping("rule.level", "rule.level", "integer", True),
        "rule_description": FieldMapping("rule.description", "rule.description", "string", True),
        "rule_groups": FieldMapping("rule.groups", "rule.groups", "array", False, []),
        "rule_firedtimes": FieldMapping("rule.firedtimes", "rule.firedtimes", "integer", False, 0),
        "rule_mail": FieldMapping("rule.mail", "rule.mail", "boolean", False, False),
        "rule_pci_dss": FieldMapping("rule.pci_dss", "rule.pci_dss", "array", False, []),
        "rule_gdpr": FieldMapping("rule.gdpr", "rule.gdpr", "array", False, []),
        "rule_hipaa": FieldMapping("rule.hipaa", "rule.hipaa", "array", False, []),
        "rule_nist_800_53": FieldMapping("rule.nist_800_53", "rule.nist_800_53", "array", False, []),
        "rule_tsc": FieldMapping("rule.tsc", "rule.tsc", "array", False, []),
        "rule_mitre_id": FieldMapping("rule.mitre.id", "rule.mitre.id", "array", False, []),
        "rule_mitre_tactic": FieldMapping("rule.mitre.tactic", "rule.mitre.tactic", "array", False, []),
        "rule_mitre_technique": FieldMapping("rule.mitre.technique", "rule.mitre.technique", "array", False, []),
        
        # Agent fields
        "agent_id": FieldMapping("agent.id", "agent.id", "string", True),
        "agent_name": FieldMapping("agent.name", "agent.name", "string", True),
        "agent_ip": FieldMapping("agent.ip", "agent.ip", "string", False),
        "agent_labels": FieldMapping("agent.labels", "agent.labels", "object", False, {}),
        
        # Manager fields
        "manager_name": FieldMapping("manager.name", "manager.name", "string", False),
        
        # Cluster fields
        "cluster_name": FieldMapping("cluster.name", "cluster.name", "string", False),
        "cluster_node": FieldMapping("cluster.node", "cluster.node", "string", False),
        
        # Location fields
        "location": FieldMapping("location", "location", "string", False),
        
        # Data fields
        "data_srcip": FieldMapping("data.srcip", "data.srcip", "string", False),
        "data_srcport": FieldMapping("data.srcport", "data.srcport", "string", False),
        "data_dstip": FieldMapping("data.dstip", "data.dstip", "string", False),
        "data_dstport": FieldMapping("data.dstport", "data.dstport", "string", False),
        "data_srcuser": FieldMapping("data.srcuser", "data.srcuser", "string", False),
        "data_dstuser": FieldMapping("data.dstuser", "data.dstuser", "string", False),
        "data_protocol": FieldMapping("data.protocol", "data.protocol", "string", False),
        "data_action": FieldMapping("data.action", "data.action", "string", False),
        "data_id": FieldMapping("data.id", "data.id", "string", False),
        "data_systemname": FieldMapping("data.system_name", "data.system_name", "string", False),
        
        # Full log fields
        "full_log": FieldMapping("full_log", "full_log", "string", False),
        
        # Previous output fields (for rules with if_matched_sid)
        "previous_output": FieldMapping("previous_output", "previous_output", "string", False),
        
        # Decoder fields
        "decoder_name": FieldMapping("decoder.name", "decoder.name", "string", False),
        "decoder_parent": FieldMapping("decoder.parent", "decoder.parent", "string", False),
        
        # Input fields
        "input_type": FieldMapping("input.type", "input.type", "string", False),
        
        # Predecoder fields
        "predecoder_program_name": FieldMapping("predecoder.program_name", "predecoder.program_name", "string", False),
        "predecoder_timestamp": FieldMapping("predecoder.timestamp", "predecoder.timestamp", "string", False),
        "predecoder_hostname": FieldMapping("predecoder.hostname", "predecoder.hostname", "string", False),
    }
    
    # Vulnerability field mappings
    VULNERABILITY_FIELD_MAPPINGS = {
        # Agent fields
        "agent_id": FieldMapping("agent.id", "agent.id", "string", True),
        "agent_name": FieldMapping("agent.name", "agent.name", "string", True),
        "agent_ip": FieldMapping("agent.ip", "agent.ip", "string", False),
        
        # Vulnerability fields
        "vulnerability_id": FieldMapping("vulnerability.id", "vulnerability.id", "string", True),
        "vulnerability_cve": FieldMapping("vulnerability.cve", "vulnerability.cve", "string", True),
        "vulnerability_title": FieldMapping("vulnerability.title", "vulnerability.title", "string", True),
        "vulnerability_severity": FieldMapping("vulnerability.severity", "vulnerability.severity", "string", True),
        "vulnerability_published": FieldMapping("vulnerability.published", "vulnerability.published", "datetime", False),
        "vulnerability_updated": FieldMapping("vulnerability.updated", "vulnerability.updated", "datetime", False),
        "vulnerability_description": FieldMapping("vulnerability.description", "vulnerability.description", "string", False),
        "vulnerability_reference": FieldMapping("vulnerability.reference", "vulnerability.reference", "string", False),
        "vulnerability_assigner": FieldMapping("vulnerability.assigner", "vulnerability.assigner", "string", False),
        "vulnerability_cvss2_score": FieldMapping("vulnerability.cvss2.score", "vulnerability.cvss2.score", "float", False),
        "vulnerability_cvss2_vector": FieldMapping("vulnerability.cvss2.vector", "vulnerability.cvss2.vector", "string", False),
        "vulnerability_cvss3_score": FieldMapping("vulnerability.cvss3.score", "vulnerability.cvss3.score", "float", False),
        "vulnerability_cvss3_vector": FieldMapping("vulnerability.cvss3.vector", "vulnerability.cvss3.vector", "string", False),
        
        # Package fields
        "package_name": FieldMapping("package.name", "package.name", "string", False),
        "package_version": FieldMapping("package.version", "package.version", "string", False),
        "package_architecture": FieldMapping("package.architecture", "package.architecture", "string", False),
        "package_format": FieldMapping("package.format", "package.format", "string", False),
        "package_condition": FieldMapping("package.condition", "package.condition", "string", False),
        
        # State fields
        "state": FieldMapping("state", "state", "string", False, "valid"),
        
        # Timestamp
        "timestamp": FieldMapping("timestamp", "@timestamp", "datetime", True),
    }
    
    # Index patterns for different data types
    INDEX_PATTERNS = {
        "alerts": "wazuh-alerts-4.x-*",
        "vulnerabilities": "wazuh-states-vulnerabilities-*", 
        "archives": "wazuh-archives-4.x-*",
        "statistics": "wazuh-statistics-*",
        "monitoring": "wazuh-monitoring-*"
    }
    
    # Sort field mappings
    SORT_FIELD_MAPPINGS = {
        "timestamp": "@timestamp",
        "-timestamp": "@timestamp",
        "rule.level": "rule.level",
        "-rule.level": "rule.level",
        "agent.name": "agent.name.keyword",  # Use keyword field for sorting
        "-agent.name": "agent.name.keyword"
    }
    
    def __init__(self, version: WazuhVersion = WazuhVersion.V4_8_X):
        self.version = version
        
    def get_alert_field_mapping(self, field_name: str) -> Optional[FieldMapping]:
        """Get field mapping for alert data."""
        return self.ALERT_FIELD_MAPPINGS.get(field_name)
    
    def get_vulnerability_field_mapping(self, field_name: str) -> Optional[FieldMapping]:
        """Get field mapping for vulnerability data."""
        return self.VULNERABILITY_FIELD_MAPPINGS.get(field_name)
    
    def map_server_to_indexer_field(self, field_name: str, data_type: str = "alert") -> str:
        """Map Server API field name to Indexer API field name."""
        mappings = (
            self.ALERT_FIELD_MAPPINGS if data_type == "alert" 
            else self.VULNERABILITY_FIELD_MAPPINGS
        )
        
        for mapping in mappings.values():
            if mapping.server_field == field_name:
                return mapping.indexer_field
        
        # Return original field name if no mapping found
        return field_name
    
    def map_indexer_to_server_field(self, field_name: str, data_type: str = "alert") -> str:
        """Map Indexer API field name to Server API field name."""
        mappings = (
            self.ALERT_FIELD_MAPPINGS if data_type == "alert" 
            else self.VULNERABILITY_FIELD_MAPPINGS
        )
        
        for mapping in mappings.values():
            if mapping.indexer_field == field_name:
                return mapping.server_field
        
        # Return original field name if no mapping found
        return field_name
    
    def get_sort_field(self, sort_param: str) -> str:
        """Get appropriate sort field for Indexer API."""
        # Handle descending sort (-)
        desc = sort_param.startswith("-")
        base_field = sort_param[1:] if desc else sort_param
        
        # Map to indexer field
        mapped_field = self.SORT_FIELD_MAPPINGS.get(base_field, base_field)
        
        return f"-{mapped_field}" if desc else mapped_field
    
    def get_index_pattern(self, data_type: str) -> str:
        """Get index pattern for data type."""
        return self.INDEX_PATTERNS.get(data_type, f"wazuh-{data_type}-*")
    
    def transform_server_response_to_indexer_format(self, server_response: Dict[str, Any], data_type: str = "alert") -> Dict[str, Any]:
        """Transform Server API response to Indexer API format for testing."""
        affected_items = server_response.get("data", {}).get("affected_items", [])
        total_count = server_response.get("data", {}).get("total_affected_items", 0)
        
        # Create mock Indexer response format
        hits = []
        for item in affected_items:
            hit = {"_source": item}
            hits.append(hit)
        
        return {
            "hits": {
                "total": {"value": total_count},
                "hits": hits
            }
        }
    
    def validate_field_compatibility(self, data: Dict[str, Any], data_type: str = "alert") -> List[str]:
        """Validate field compatibility and return list of issues."""
        issues = []
        mappings = (
            self.ALERT_FIELD_MAPPINGS if data_type == "alert" 
            else self.VULNERABILITY_FIELD_MAPPINGS
        )
        
        # Check for required fields
        for field_key, mapping in mappings.items():
            if mapping.required:
                # Check both server and indexer field formats
                server_field_exists = self._check_nested_field(data, mapping.server_field)
                indexer_field_exists = self._check_nested_field(data, mapping.indexer_field)
                
                if not server_field_exists and not indexer_field_exists:
                    issues.append(f"Required field missing: {mapping.server_field} / {mapping.indexer_field}")
        
        return issues
    
    def _check_nested_field(self, data: Dict[str, Any], field_path: str) -> bool:
        """Check if nested field exists in data."""
        keys = field_path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return False
        
        return True
    
    def get_field_default_value(self, field_name: str, data_type: str = "alert") -> Any:
        """Get default value for a field."""
        mappings = (
            self.ALERT_FIELD_MAPPINGS if data_type == "alert" 
            else self.VULNERABILITY_FIELD_MAPPINGS
        )
        
        mapping = mappings.get(field_name)
        return mapping.default_value if mapping else None
    
    def sanitize_query_fields(self, query_params: Dict[str, Any], data_type: str = "alert") -> Dict[str, Any]:
        """Sanitize query parameters to use correct field names for version."""
        sanitized = {}
        
        for key, value in query_params.items():
            # Map field names if needed
            if data_type == "alert":
                # Handle common query parameters
                if key == "level":
                    sanitized["rule.level"] = value
                elif key == "agent_id" or key == "agent.id":
                    sanitized["agent.id"] = value
                elif key == "sort":
                    sanitized[key] = self.get_sort_field(value)
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value
        
        return sanitized