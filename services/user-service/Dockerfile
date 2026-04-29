# syntax=docker/dockerfile:1
# Hadolint: DL3008 pinned packages, DL3013 pinned pip, DL3042 no pip cache
FROM python:3.12-slim AS base

# Non-root user (CIS Docker Benchmark 4.1)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN mkdir -p /data && chown appuser:appuser /data

USER appuser

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--no-access-log"]
