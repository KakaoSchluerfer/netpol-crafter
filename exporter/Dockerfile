FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

COPY --chown=1000:1000 exporter/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=1000:1000 exporter/ exporter/
# k8s/fixtures.py is loaded dynamically in TEST_MODE only
COPY --chown=1000:1000 k8s/ k8s/

USER 1000

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

CMD ["uvicorn", "exporter.main:app", "--host", "0.0.0.0", "--port", "8080"]
