# Use the official Bun image
FROM oven/bun:1.1-alpine AS base

# Set working directory
WORKDIR /app

# Install dependencies first (for better caching)
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy source code
COPY . .

# Build the application
RUN bun run build

# Set production environment
ENV NODE_ENV=production

# Make the binary executable
RUN chmod +x build/index.js

# Expose port if needed (uncomment if your app serves HTTP)
# EXPOSE 3000

# Run the application
CMD ["bun", "run", "start:prod"]
