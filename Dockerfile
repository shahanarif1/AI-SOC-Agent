# Dockerfile for Remote MCP Server
FROM python:3.11-slim

# Set labels for identification
LABEL maintainer="Wazuh MCP Team <support@wazuh.com>"
LABEL description="Wazuh MCP Server - Remote Access"
LABEL version="1.1.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Create app user for security
RUN groupadd -r wazuh && useradd -r -g wazuh wazuh

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir websockets aiohttp aiohttp-cors

# Copy application code
COPY src/ ./src/
COPY wazuh_mcp_server.py ./

# Install the package
RUN pip install --no-cache-dir -e .

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data && \
    chown -R wazuh:wazuh /app

# Switch to non-root user
USER wazuh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose ports
EXPOSE 8000 8001

# Default command (can be overridden)
CMD ["python", "wazuh_mcp_server.py", "--http", "--host", "0.0.0.0", "--port", "8000"]