# =============================================================================
# ReconScope Frontend — Multi-stage Dockerfile
# =============================================================================

# ─── Stage 1: Builder (production build) ─────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests and install
COPY package*.json ./
RUN npm ci

# Copy source and build for production
COPY . .
RUN npm run build

# ─── Stage 2: Dev (used by docker-compose for development) ───────────────────
FROM node:20-alpine AS dev

WORKDIR /app

# Copy dependency manifests and install
COPY package*.json ./
RUN npm ci

# Copy all source files
COPY . .

# Ensure the node user owns the working directory for Vite temp files
RUN chown -R node:node /app

EXPOSE 3000

# Use the built-in node user (UID 1000, exists in node:alpine)
USER node

# Start Vite dev server, bind to all interfaces for Docker networking
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
