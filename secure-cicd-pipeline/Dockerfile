# Use a specific version for better security
FROM node:18-alpine AS build

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies with exact versions
RUN npm ci --only=production

# Copy application code
COPY . .

# Remove any sensitive data or development files
RUN rm -rf tests .git .github .env* 

# Use multi-stage build for smaller final image
FROM node:18-alpine AS runtime

# Set environment variables
ENV NODE_ENV=production \
    PORT=3000 \
    # Disable npm update checks
    NPM_CONFIG_UPDATE_NOTIFIER=false

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy from build stage
COPY --from=build --chown=appuser:appgroup /app ./

# Set proper permissions
RUN chmod -R 755 /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/ || exit 1

# Start application
CMD ["node", "app.js"]
