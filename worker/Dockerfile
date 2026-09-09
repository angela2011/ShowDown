FROM python:3.12-slim

WORKDIR /app
COPY worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /shared
RUN pip install --no-cache-dir /shared

COPY worker/worker ./worker

CMD ["python", "-m", "worker.main"]
