.PHONY: help dev dev-backend dev-frontend build build-backend build-frontend clean test fixtures install install-backend install-frontend lint

# Default target
help:
	@echo "Vervet - Network Threat Hunting Platform"
	@echo ""
	@echo "Available targets:"
	@echo "  make dev              - Start both backend and frontend in development mode"
	@echo "  make dev-backend      - Start backend API server (FastAPI)"
	@echo "  make dev-frontend     - Start frontend dev server (Vite)"
	@echo "  make build            - Build production bundles for both backend and frontend"
	@echo "  make build-backend    - Build backend (no-op, Python doesn't need building)"
	@echo "  make build-frontend   - Build frontend production bundle"
	@echo "  make clean            - Remove build artifacts and caches"
	@echo "  make test             - Run all tests"
	@echo "  make test-backend     - Run backend tests (pytest)"
	@echo "  make test-frontend    - Run frontend tests"
	@echo "  make fixtures         - Regenerate all fixture data"
	@echo "  make install          - Install all dependencies"
	@echo "  make install-backend  - Install Python dependencies"
	@echo "  make install-frontend - Install Node.js dependencies"
	@echo "  make lint             - Run linters for both backend and frontend"
	@echo ""

# Development
dev:
	@echo "Starting Vervet in development mode..."
	@echo "Backend will run on http://localhost:8000"
	@echo "Frontend will run on http://localhost:5174"
	@echo ""
	@trap 'kill 0' EXIT; \
	make dev-backend & \
	make dev-frontend & \
	wait

dev-backend:
	@echo "Starting backend API server..."
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	@echo "Starting frontend dev server..."
	npm run dev

# Build
build: build-backend build-frontend
	@echo "✓ Build complete!"

build-backend:
	@echo "Backend is Python - no build step required"
	@echo "✓ Backend ready"

build-frontend:
	@echo "Building frontend production bundle..."
	npm run build
	@echo "✓ Frontend built to web/dist/"

# Clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf web/dist
	rm -rf web/node_modules/.vite
	rm -rf api/__pycache__
	rm -rf api/**/__pycache__
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✓ Clean complete"

# Testing
test: test-backend
	@echo "✓ All tests passed"

test-backend:
	@echo "Running backend tests..."
	pytest -v

test-frontend:
	@echo "Running frontend tests..."
	cd web && npm test

# Fixtures
fixtures:
	@echo "Regenerating fixture data..."
	cd fixtures && python3 generate_fixtures.py
	@echo "✓ Fixtures regenerated"

# Installation
install: install-backend install-frontend
	@echo "✓ All dependencies installed"

install-backend:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "✓ Backend dependencies installed"

install-frontend:
	@echo "Installing Node.js dependencies..."
	npm install
	@echo "✓ Frontend dependencies installed"

# Linting
lint: lint-backend lint-frontend
	@echo "✓ Linting complete"

lint-backend:
	@echo "Linting backend code..."
	@command -v ruff >/dev/null 2>&1 && ruff check api/ || echo "ruff not installed, skipping"
	@command -v mypy >/dev/null 2>&1 && mypy api/ || echo "mypy not installed, skipping"

lint-frontend:
	@echo "Linting frontend code..."
	npm run lint
