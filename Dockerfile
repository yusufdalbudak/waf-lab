# Multi-stage build for optimized, secure production image
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r waf && useradd -r -g waf waf

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code (auth included)
COPY --chown=waf:waf waf.py rules.json /app/
COPY --chown=waf:waf config/ /app/config/
COPY --chown=waf:waf logger/ /app/logger/
COPY --chown=waf:waf inspector/ /app/inspector/
COPY --chown=waf:waf router/ /app/router/
COPY --chown=waf:waf utils/ /app/utils/
COPY --chown=waf:waf metrics/ /app/metrics/
COPY --chown=waf:waf auth/ /app/auth/
COPY --chown=waf:waf core/ /app/core/

# Create log directory with proper permissions
RUN mkdir -p /app/logs && chown -R waf:waf /app/logs

# Security: Drop privileges
USER waf

# Health check (make sure your app exposes /healthz; change if needed)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; \
    r=urllib.request.urlopen('http://127.0.0.1:8000/healthz'); \
    sys.exit(0 if r.getcode()==200 else 1)"

# Expose WAF port
EXPOSE 8000

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV WAF_PORT=8000
ENV WAF_HOST=0.0.0.0

# Run application
CMD ["python", "waf.py"]
