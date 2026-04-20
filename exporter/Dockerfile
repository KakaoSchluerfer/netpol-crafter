FROM python:3.11-slim
WORKDIR /app
COPY exporter/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER 1000
EXPOSE 8080
CMD ["uvicorn", "exporter.main:app", "--host", "0.0.0.0", "--port", "8080"]
