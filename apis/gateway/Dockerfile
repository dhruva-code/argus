FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY apis/gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY apis/gateway/ /app/

RUN chmod +x /app/entrypoint.sh && \
    adduser --disabled-password --gecos "" argus && chown -R argus /app
USER argus

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["/app/entrypoint.sh"]
