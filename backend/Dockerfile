# =============================================================================
# ReconScope Backend — Multi-stage Dockerfile
# =============================================================================

# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies needed for compiling Python packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Install only the runtime libraries (no compilers)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
        nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Create non-root user
RUN groupadd --gid 1001 appuser && \
    useradd --uid 1001 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# Copy application code
COPY . .

# Ensure the app directory is owned by appuser
RUN chown -R appuser:appuser /app

EXPOSE 8000

# Switch to non-root user
USER appuser

# Default command — overridden in docker-compose for worker/flower
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
