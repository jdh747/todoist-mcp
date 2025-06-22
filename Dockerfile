# Use the official Bun image (latest stable)
FROM oven/bun:latest AS base

# Set working directory
WORKDIR /app

# Install dependencies first (for better caching)
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production --ignore-scripts

# Copy source code
COPY . .

# Install dev dependencies for build
RUN bun install --frozen-lockfile

# Build the application
RUN bun run build

# Set production environment
ENV NODE_ENV=production

# Make the binary executable
RUN chmod +x build/index.js

# Run the application
CMD ["bun", "run", "start:prod"]
