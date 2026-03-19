#!/usr/bin/env bash
# ============================================================
# reNgine-ng Custom Config Deploy Script
# Author: pt-zenity | Date: 2026-03-19
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_STATIC="/home/rengine/rengine-ng/web/static/custom"
WEB_STATIC_FILES="/home/rengine/rengine-ng/web/staticfiles/custom"

echo "=== reNgine-ng Deploy: pt-zenity custom config ==="
echo "Source: $SCRIPT_DIR"

# ── 1. CSS Theme ─────────────────────────────────────────────
echo ""
echo "[1/3] Deploying CSS theme v3.0.0..."
mkdir -p "$WEB_STATIC" "$WEB_STATIC_FILES" 2>/dev/null || true
cp "$SCRIPT_DIR/custom-css-v3/custom.css" "$WEB_STATIC/custom.css" && echo "  ✓ Host static"
cp "$SCRIPT_DIR/custom-css-v3/custom.css" "$WEB_STATIC_FILES/custom.css" && echo "  ✓ Host staticfiles"
docker cp "$SCRIPT_DIR/custom-css-v3/custom.css" rengine-web-1:/home/rengine/rengine/static/custom/custom.css && echo "  ✓ Container static"
docker cp "$SCRIPT_DIR/custom-css-v3/custom.css" rengine-web-1:/home/rengine/rengine/staticfiles/custom/custom.css && echo "  ✓ Container staticfiles"

# ── 2. Nuclei Templates ──────────────────────────────────────
echo ""
echo "[2/3] Deploying 29 custom Nuclei templates..."
docker cp "$SCRIPT_DIR/custom-nuclei-templates/." rengine-celery-1:/home/rengine/nuclei-templates/http/custom/
COUNT=$(docker exec rengine-celery-1 find /home/rengine/nuclei-templates/http/custom -name "*.yaml" | wc -l)
echo "  ✓ $COUNT templates deployed"

# Copy to Docker volume for persistence
docker run --rm \
  -v rengine_nuclei_templates:/nuclei \
  -v "$SCRIPT_DIR/custom-nuclei-templates":/src:ro \
  alpine sh -c "mkdir -p /nuclei/http/custom && cp -r /src/. /nuclei/http/custom/" 2>/dev/null && \
  echo "  ✓ Volume copy complete" || echo "  ⚠ Volume copy failed (non-fatal)"

# ── 3. Scan Engines ──────────────────────────────────────────
echo ""
echo "[3/3] Restoring custom scan engines..."
docker cp "$SCRIPT_DIR/fast-scan-engines/restore_all_engines.sql" rengine-db-1:/tmp/
docker exec rengine-db-1 sh -c 'psql -U rengine -d rengine -f /tmp/restore_all_engines.sql' 2>&1 | grep -E "INSERT|ERROR" || true
ECOUNT=$(docker exec rengine-db-1 sh -c "psql -U rengine -d rengine -t -c \"SELECT COUNT(*) FROM \\\"scanEngine_enginetype\\\" WHERE id >= 18;\"" 2>/dev/null | tr -d ' ')
echo "  ✓ $ECOUNT custom engines present (IDs 18+)"

echo ""
echo "=== Deploy complete ==="
echo "  CSS: https://YOUR_IP/staticfiles/custom/custom.css"
echo "  Engines: Login → Scan → Select 'Fast -' or 'Custom -' engine"
echo "  Nuclei: Use custom_templates: [http/custom/...] in engine YAML"
