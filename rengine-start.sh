#!/bin/bash
# reNgine Auto-Start Script
# Dipanggil oleh systemd saat server boot

LOG="/var/log/rengine-startup.log"
DOCKER_DIR="/home/rengine/docker"
ENV_FILE="/home/rengine/.env"

echo "[$(date)] === reNgine Startup ===" >> $LOG

# Pastikan Docker running
for i in {1..10}; do
    if docker info >/dev/null 2>&1; then
        echo "[$(date)] Docker is ready" >> $LOG
        break
    fi
    echo "[$(date)] Waiting for Docker... ($i/10)" >> $LOG
    sleep 3
done

# Start containers
cd $DOCKER_DIR
echo "[$(date)] Starting containers..." >> $LOG
RENGINE_VERSION=3.0.0 docker compose --env-file $ENV_FILE up -d >> $LOG 2>&1

# Tunggu web container healthy
echo "[$(date)] Waiting for web container to be healthy..." >> $LOG
for i in {1..30}; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' rengine-web-1 2>/dev/null)
    if [ "$STATUS" = "healthy" ]; then
        echo "[$(date)] Web container is healthy!" >> $LOG
        break
    fi
    echo "[$(date)] Web status: $STATUS ($i/30)" >> $LOG
    sleep 5
done

# Reload nginx proxy to refresh DNS after all containers get their IPs
echo "[$(date)] Reloading nginx proxy to refresh DNS..." >> $LOG
sleep 3
docker exec rengine-proxy-1 nginx -s reload >> $LOG 2>&1

echo "[$(date)] === Startup complete ===" >> $LOG
