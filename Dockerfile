FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies (git needed for compliance repo cloning)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev git && \
    rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Create non-root user
RUN groupadd --gid 1000 anaya && \
    useradd --uid 1000 --gid 1000 --create-home anaya

WORKDIR /app

# Copy all application code
COPY . .

# Install package with all dependencies
RUN uv pip install --system -e ".[dev]"

# Switch to non-root user
USER anaya

EXPOSE 8000

# Production command
CMD ["uvicorn", "anaya.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
