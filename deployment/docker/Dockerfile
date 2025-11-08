# Jarvis P2P Encrypted Messenger - Docker Image
# Multi-stage build for minimal image size
# Created by orpheus497

# Build stage
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN groupadd -r jarvis && useradd -r -g jarvis -d /home/jarvis -m jarvis

# Set up application directory
WORKDIR /app
COPY --chown=jarvis:jarvis src /app/src
COPY --chown=jarvis:jarvis pyproject.toml README.md LICENSE.txt CHANGELOG.md /app/

# Install application
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -e .

# Create data directory
RUN mkdir -p /data/jarvis && chown -R jarvis:jarvis /data/jarvis

# Switch to non-root user
USER jarvis

# Expose default ports
# 5000: P2P messaging port (configurable)
# 5999: IPC port for client-server communication
# 6881: DHT port (configurable)
EXPOSE 5000 5999 6881

# Environment variables
ENV JARVIS_DATA_DIR=/data/jarvis
ENV JARVIS_LOG_LEVEL=INFO

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -f "jarvis.server" > /dev/null || exit 1

# Default command: start server
CMD ["python", "-m", "jarvis.server", "--data-dir", "/data/jarvis", "--ipc-port", "5999"]
