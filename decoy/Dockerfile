FROM python:3.12-slim
WORKDIR /app
COPY decoy/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home decoy && mkdir /data && chown decoy:decoy /data
COPY decoy /app/decoy
USER 10001
ENV PYTHONDONTWRITEBYTECODE=1 DECOY_OUTBOX=/data/outbox.sqlite
EXPOSE 9080 9021
CMD ["python", "-m", "decoy.service"]
