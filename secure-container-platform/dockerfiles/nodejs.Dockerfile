# Secure Node.js Dockerfile
# Multi-stage build for minimal attack surface

# ---- Build Stage ----
FROM node:18-alpine AS build

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies with exact versions and clean npm cache
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application code
COPY . .

# Remove any sensitive data or development files
RUN rm -rf tests .git .github .env* 

# ---- Runtime Stage ----
FROM node:18-alpine AS runtime

# Set environment variables
ENV NODE_ENV=production \
    PORT=3000 \
    # Disable npm update checks
    NPM_CONFIG_UPDATE_NOTIFIER=false

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup && \
    # Create app directory and set permissions
    mkdir -p /app && \
    chown -R appuser:appgroup /app

# Set working directory
WORKDIR /app

# Copy from build stage
COPY --from=build --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=build --chown=appuser:appgroup /app/package.json ./
COPY --from=build --chown=appuser:appgroup /app/src ./src

# Set proper permissions
RUN chmod -R 755 /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

# Security hardening
# Add security labels
LABEL org.opencontainers.image.vendor="Secure Container Platform" \
      org.opencontainers.image.title="Secure Node.js Application" \
      org.opencontainers.image.description="Secure Node.js application with minimal attack surface" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.created="2025-05-30" \
      security.alpha.kubernetes.io/seccomp=runtime/default \
      security.alpha.kubernetes.io/capabilities=drop:all

# Start application
CMD ["node", "src/index.js"]
