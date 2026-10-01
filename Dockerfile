# syntax=docker/dockerfile:1

# --- Stage 1: build the React frontend -------------------------------------
FROM node:20-slim AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
# tailwind.config.js is resolved from the build cwd (/app) by web/postcss.config.js.
COPY tailwind.config.js ./
COPY web/ ./web/
RUN npm run build          # emits /app/web/dist

# --- Stage 2: install Python deps ------------------------------------------
# xhtml2pdf (PDF reports) pulls in pycairo, which compiles from source and needs
# a C compiler + cairo headers. Do that here so the runtime image stays slim.
FROM python:3.12-slim AS pybuild
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libcairo2-dev && \
    rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 3: slim runtime (no compiler, no Node, no headers) --------------
FROM python:3.12-slim AS runtime
# libcairo2 is the runtime shared library pycairo needs at import time.
RUN apt-get update && apt-get install -y --no-install-recommends libcairo2 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=pybuild /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY api/ ./api/
COPY data/ ./data/
COPY --from=frontend /app/web/dist ./web/dist

# When not in demo mode, ingested logs persist under /data and survive restarts.
# Mount a volume at /data (see docker-compose.yml) to keep them across recreates.
ENV PORT=8000 VERVET_DATA_DIR=/data
RUN mkdir -p /data

EXPOSE 8000
CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}
