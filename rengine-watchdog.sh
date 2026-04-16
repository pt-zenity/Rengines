#!/bin/bash
# reNgine Watchdog - Jalankan setiap 2 menit via crontab
# Auto-fix jika web tidak bisa diakses via proxy

LOG="/var/log/rengine-watchdog.log"
MAX_LOG_SIZE=1048576  # 1MB

# Rotate log jika terlalu besar
if [ -f "$LOG" ] && [ $(stat -c%s "$LOG" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]; then
    mv "$LOG" "${LOG}.old"
fi

# Cek apakah web bisa diakses via HTTPS
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 https://127.0.0.1/ 2>/dev/null)

if [ "$HTTP_CODE" = "000" ] || [ "$HTTP_CODE" = "502" ] || [ "$HTTP_CODE" = "503" ]; then
    echo "[$(date)] WARNING: Web not accessible (HTTP $HTTP_CODE). Attempting fix..." >> $LOG

    # Cek apakah web container healthy
    WEB_STATUS=$(docker inspect --format='{{.State.Health.Status}}' rengine-web-1 2>/dev/null)
    
    if [ "$WEB_STATUS" = "healthy" ]; then
        # Web OK tapi proxy tidak bisa reach - reload nginx DNS
        echo "[$(date)] Web is healthy, reloading nginx DNS..." >> $LOG
        docker exec rengine-proxy-1 nginx -s reload >> $LOG 2>&1
        sleep 2
        
        # Verifikasi setelah reload
        HTTP_CODE2=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 https://127.0.0.1/ 2>/dev/null)
        echo "[$(date)] After nginx reload: HTTP $HTTP_CODE2" >> $LOG
    else
        # Web tidak healthy - restart web container
        echo "[$(date)] Web status: $WEB_STATUS. Restarting web container..." >> $LOG
        docker restart rengine-web-1 >> $LOG 2>&1
        sleep 30
        docker exec rengine-proxy-1 nginx -s reload >> $LOG 2>&1
        echo "[$(date)] Web restarted and nginx reloaded" >> $LOG
    fi
else
    # Semua OK - silent (tidak log agar tidak spam)
    :
fi
