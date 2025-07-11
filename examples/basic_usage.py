#!/usr/bin/env python3
"""
Basic Usage Examples for Wazuh MCP Server

This file demonstrates basic usage patterns and queries
that can be performed with the Wazuh MCP Server.
"""

# Example queries you can ask Claude Desktop when connected to Wazuh MCP Server

BASIC_QUERIES = [
    # Security Monitoring
    "Show me recent security alerts",
    "What are the critical alerts from the last 24 hours?",
    "Get alerts with level 10 or higher",
    "Show me alerts from agent 001",
    
    # Agent Health
    "What's the status of my Wazuh agents?",
    "Check the health of agent 002",
    "Show me inactive agents",
    "Get agent health summary",
    
    # Threat Analysis
    "Analyze threats in the last hour",
    "What security threats were detected today?",
    "Analyze suspicious activity patterns",
    "Perform threat hunting analysis",
    
    # Compliance
    "Run a PCI DSS compliance check",
    "Check GDPR compliance status",
    "Perform HIPAA compliance assessment",
    "Show compliance violations",
    
    # Vulnerabilities
    "Show me critical vulnerabilities",
    "Get vulnerability summary for all agents",
    "What are the high-risk vulnerabilities?",
    "Prioritize vulnerabilities by risk",
    
    # System Monitoring
    "Show Wazuh cluster status",
    "Get system statistics",
    "Check log collector performance",
    "Monitor remoted communication",
]

ADVANCED_QUERIES = [
    # Incident Investigation
    "Investigate the security incident on agent 003",
    "Build a timeline for the breach on January 15th",
    "Correlate alerts with process activity",
    "Analyze lateral movement indicators",
    
    # Forensic Analysis
    "Search manager logs for authentication failures",
    "Find evidence of privilege escalation",
    "Trace suspicious network connections",
    "Analyze file system changes",
    
    # Network Security
    "Check for suspicious open ports",
    "Detect potential backdoors",
    "Analyze network exposure",
    "Monitor unusual network activity",
    
    # Process Analysis
    "Find suspicious running processes",
    "Detect malicious process behavior",
    "Analyze process execution patterns",
    "Check for privilege escalation attempts",
]

PROMPT_ENHANCEMENT_EXAMPLES = [
    # These queries will automatically trigger context aggregation
    "Investigate this security incident thoroughly",  # Triggers incident pipeline
    "Hunt for advanced persistent threats",           # Triggers hunting pipeline
    "Assess our compliance posture",                  # Triggers compliance pipeline
    "Perform forensic analysis of the breach",        # Triggers forensic pipeline
]

def print_examples():
    """Print usage examples for demonstration."""
    print("=== WAZUH MCP SERVER USAGE EXAMPLES ===\n")
    
    print("📊 BASIC QUERIES:")
    print("Ask Claude Desktop these questions after connecting to Wazuh MCP Server:\n")
    
    for i, query in enumerate(BASIC_QUERIES, 1):
        print(f"{i:2d}. {query}")
    
    print(f"\n🔍 ADVANCED QUERIES:")
    print("For more sophisticated security analysis:\n")
    
    for i, query in enumerate(ADVANCED_QUERIES, 1):
        print(f"{i:2d}. {query}")
    
    print(f"\n🤖 PROMPT ENHANCEMENT EXAMPLES:")
    print("These queries trigger automatic context gathering (Phase 5):\n")
    
    for i, query in enumerate(PROMPT_ENHANCEMENT_EXAMPLES, 1):
        print(f"{i:2d}. {query}")
    
    print(f"\n💡 TIPS:")
    print("- Be specific about time ranges (e.g., 'last 24 hours', 'today')")
    print("- Include agent IDs when investigating specific systems")
    print("- Use natural language - the system understands context")
    print("- Ask follow-up questions to drill down into details")
    print("- Request summaries for high-level overviews")

if __name__ == "__main__":
    print_examples()