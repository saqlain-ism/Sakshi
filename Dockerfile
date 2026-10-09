# One image for every role. SAKSHI_ROLE picks what a container runs:
#   all (default) - the whole network in one process (local demo, free hosting)
#   registry | gateway | ledger | issuer | bap | bpp | console - one service each (docker compose)
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PORT=8000 SAKSHI_ROLE=all
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[network]" && useradd --create-home sakshi && mkdir -p /data && chown sakshi /data
USER sakshi

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\", \"8000\")}/healthz', timeout=2)"
CMD ["sh", "-c", "uvicorn sakshi_network.app:create_app --factory --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
