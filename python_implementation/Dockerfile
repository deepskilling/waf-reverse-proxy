# PyWAF - Web Application Firewall & Reverse Proxy
# Complete Python implementation by Deepskilling

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install PyWAF in development mode
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 pywaf && \
    chown -R pywaf:pywaf /app

# Create directories for certificates and logs
RUN mkdir -p /app/certs /app/logs && \
    chown -R pywaf:pywaf /app/certs /app/logs

# Switch to non-root user
USER pywaf

# Expose ports
EXPOSE 8080 8443 8081 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["pywaf", "server", "start", "--config", "config/config.yaml"]
