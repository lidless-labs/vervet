FROM node:22-bookworm-slim AS frontend
WORKDIR /build
ENV NODE_OPTIONS=--max-old-space-size=2048
COPY package*.json tailwind.config.* ./
COPY web/ ./web/
RUN npm ci && npm run build

FROM python:3.12-slim-bookworm AS python-build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libcairo2-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.txt ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libcairo2 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 vervet && \
    useradd --uid 10001 --gid vervet --no-create-home vervet
WORKDIR /app
COPY requirements.txt ./
COPY --from=python-build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt && \
    rm -rf /wheels
COPY --from=frontend /build/web/dist ./web/dist
COPY api/ ./api/
COPY --chown=vervet:vervet data/ ./data/
RUN mkdir -p /app/data && chown -R vervet:vervet /app/data
USER vervet
ENV PORT=8000 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    VERVET_SETTINGS_FILE=/app/data/vervet_settings.json \
    VERVET_SCORING_WEIGHTS_FILE=/app/data/scoring_weights.json
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
