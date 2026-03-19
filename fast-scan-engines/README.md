# Fast Scan Engines — pt-zenity reNgine-ng

5 scan engine khusus kecepatan untuk reNgine-ng v3.0.0.
Dibuat: 2026-03-19 | Author: pt-zenity

---

## Engine List

| ID | Name | Use Case | Est. Time | Tools |
|----|------|----------|-----------|-------|
| 18 | **Fast - Lightning Recon** | Subdomain discovery saja | ~3-5 min | subfinder, ctfr, tlsx, httpx |
| 19 | **Fast - Quick Vuln (High+Critical)** | Nuclei high+critical subscan | ~5-10 min | nuclei (high/critical only) |
| 20 | **Fast - Speed Bug Bounty (Full)** | Full pipeline dioptimasi | ~15-25 min | subfinder+katana+nuclei(med-crit) |
| 21 | **Fast - Ultra Port Scan (top100)** | Port scan super cepat | ~2-5 min | naabu top-100 |
| 22 | **Fast - Subdomain + Screenshot** | Visual recon overview | ~8-12 min | subfinder+httpx+gowitness |

---

## Perbandingan Kecepatan vs Default

| Parameter | Default Recommended | Fast Engines |
|-----------|---------------------|--------------|
| Threads | 30 | 50-100 |
| Timeout | 5s | 3-4s |
| Rate limit | 150/s | 200-500/s |
| Retries | 1 | 0 |
| Tools subdomain | 6 tools | 3 tools terbaik |
| Nuclei severity | all (6) | high+critical atau med-crit |

---

## Cara Install Ulang

Jika database di-reset, jalankan:
```bash
docker cp /home/rengine/webapp/fast-scan-engines/insert_engines.sql rengine-db-1:/tmp/
docker exec rengine-db-1 sh -c 'psql -U rengine -d rengine -f /tmp/insert_engines.sql'
```

