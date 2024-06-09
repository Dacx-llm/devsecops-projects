# Secure Python Dockerfile
# Multi-stage build for minimal attack surface

# ---- Build Stage ----
FROM python:3.11-slim AS build

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# ---- Runtime Stage ----
FROM python:3.11-slim AS runtime

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Create a non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser && \
    mkdir -p /app && \
    chown -R appuser:appgroup /app

# Set working directory
WORKDIR /app

# Copy only necessary files from build stage
COPY --from=build --chown=appuser:appgroup /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=build --chown=appuser:appgroup /app/app ./app
COPY --from=build --chown=appuser:appgroup /app/main.py .

# Set proper permissions
RUN chmod -R 755 /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Security hardening
# Add security labels
LABEL org.opencontainers.image.vendor="Secure Container Platform" \
      org.opencontainers.image.title="Secure Python Application" \
      org.opencontainers.image.description="Secure Python application with minimal attack surface" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.created="2025-05-30" \
      security.alpha.kubernetes.io/seccomp=runtime/default \
      security.alpha.kubernetes.io/capabilities=drop:all

# Start application
CMD ["python", "main.py"]
