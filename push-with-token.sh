#!/usr/bin/env bash
# ============================================================
# Push reNgine-ng custom configs ke GitHub
# Author: pt-zenity
# Usage: ./push-with-token.sh <YOUR_GITHUB_TOKEN>
# ============================================================

TOKEN="${1:-}"
if [ -z "$TOKEN" ]; then
    echo "Usage: $0 <github_personal_access_token>"
    echo ""
    echo "Cara buat token baru (berlaku 6 bulan):"
    echo "  1. Login ke https://github.com/settings/tokens/new"
    echo "  2. Note: 'reNgine-ng deploy token'"
    echo "  3. Expiration: Custom -> pilih 6 months"
    echo "  4. Scopes: centang 'repo' (full control)"
    echo "  5. Klik 'Generate token' -> copy token"
    echo "  6. Jalankan: $0 ghp_xxxxxxxxxxxxxxxxxxxx"
    exit 1
fi

echo "=== Push ke GitHub: pt-zenity/Rengines ==="

# Update credentials
echo "https://x-access-token:${TOKEN}@github.com" > ~/.git-credentials
chmod 600 ~/.git-credentials
echo "  ✓ Credentials diupdate"

# Update remote URL
cd /home/rengine/webapp
git remote set-url origin "https://x-access-token:${TOKEN}@github.com/pt-zenity/Rengines.git"

# Test token
USER=$(curl -s -H "Authorization: token $TOKEN" "https://api.github.com/user" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('login', 'FAILED: '+d.get('message','')))" 2>/dev/null)
echo "  Token valid untuk user: $USER"

if [[ "$USER" == "FAILED"* ]]; then
    echo "  ✗ Token tidak valid! Cek kembali token Anda."
    exit 1
fi

# Push
echo "  Pushing ke origin/main..."
git push -u origin main 2>&1
EXIT=$?

if [ $EXIT -eq 0 ]; then
    echo ""
    echo "=== BERHASIL! ==="
    echo "  Repository: https://github.com/pt-zenity/Rengines"
    echo "  Branch: main"
    echo "  Commit: $(git log --oneline -1)"
    echo ""
    echo "  Juga update token di nested repos..."
    
    # Update rengine-patches remote
    cd /home/rengine/webapp/rengine-patches 2>/dev/null && \
        git remote set-url origin "https://x-access-token:${TOKEN}@github.com/pt-zenity/rengine-ng-vps-patches.git" && \
        echo "  ✓ rengine-patches remote updated"
    
    # Update rengine-deploy remote
    cd /home/rengine/webapp/rengine-deploy 2>/dev/null && \
        git remote set-url origin "https://x-access-token:${TOKEN}@github.com/pt-zenity/rengine-ng-deploy.git" && \
        echo "  ✓ rengine-deploy remote updated"
    
    # Update ptzenity-website remote
    cd /home/rengine/webapp/ptzenity-website 2>/dev/null && \
        git remote set-url origin "https://x-access-token:${TOKEN}@github.com/pt-zenity/ptzenity-website.git" && \
        echo "  ✓ ptzenity-website remote updated"
else
    echo ""
    echo "  ✗ Push gagal (exit code $EXIT)"
    echo "  Pastikan token memiliki scope 'repo'"
fi
