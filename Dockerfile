# CyberPot Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY scripts/ ./scripts/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Create necessary directories
RUN mkdir -p /app/config /app/data /app/logs && \
    mkdir -p /app/data/geoip /app/data/blocklists

# Create non-root user
RUN useradd -m -u 1000 cyberpot && \
    chown -R cyberpot:cyberpot /app

USER cyberpot

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV CYBERPOT_CONFIG=/app/config/cyberpot.yaml

# Default command (headless mode)
CMD ["python", "-m", "cyberpot", "start", "--mode", "headless", "--config", "/app/config/cyberpot.yaml"]
