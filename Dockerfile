FROM python:3.12-slim

# Install Node for the frontend build, plus the toolchain pycairo needs.
# xhtml2pdf (PDF reports) pulls in pycairo, which compiles from source and
# requires a C compiler + cairo headers; the runtime needs libcairo2.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl build-essential pkg-config libcairo2-dev && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Frontend: install deps at root, build from web/
COPY package*.json tailwind.config.* tsconfig.* ./
COPY web/ ./web/
RUN npm install \
    && npm run build \
    && rm -rf node_modules

# Backend
COPY api/ ./api/

# Data (demo logs, sigma rules, cases dir)
COPY data/ ./data/

ENV PORT=8000
EXPOSE 8000

CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}
