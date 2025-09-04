# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     PIP_NO_CACHE_DIR=1

# Non-root user
RUN useradd -u 10001 -ms /bin/bash appuser
WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends     ca-certificates     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY tools ./tools
COPY config ./config
COPY keys ./keys
COPY .env ./.env

RUN mkdir -p var/data && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080
CMD ["uvicorn", "src.signet.app:app", "--host", "0.0.0.0", "--port", "8080"]
