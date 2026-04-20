FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Dependency layer — cached unless requirements.txt changes
COPY --chown=1000:1000 requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Source — owned by appuser at copy time, no chown -R needed
COPY --chown=1000:1000 app.py config.py ./
COPY --chown=1000:1000 .streamlit/ .streamlit/
COPY --chown=1000:1000 auth/ auth/
COPY --chown=1000:1000 k8s/ k8s/
COPY --chown=1000:1000 pages/ pages/
COPY --chown=1000:1000 ui/ ui/

USER 1000

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -sf http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true", \
    "--server.enableCORS=false", \
    "--server.enableXsrfProtection=true"]
