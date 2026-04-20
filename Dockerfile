FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Dependency layer — cached unless requirements.txt changes
COPY --chown=1000:1000 requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY --chown=1000:1000 app.py config.py ./
COPY --chown=1000:1000 .streamlit/ .streamlit/
COPY --chown=1000:1000 auth/ auth/
COPY --chown=1000:1000 k8s/ k8s/
COPY --chown=1000:1000 pages/ pages/
COPY --chown=1000:1000 ui/ ui/
COPY --chown=1000:1000 exporter/ exporter/

USER 1000

# No default CMD — the Kubernetes Deployment (or docker-compose service) sets
# the command to either the Streamlit app or the uvicorn exporter.
