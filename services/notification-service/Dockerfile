# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN mkdir -p /data && chown appuser:appuser /data

USER appuser

EXPOSE 8005

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8005/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005", "--no-access-log"]
