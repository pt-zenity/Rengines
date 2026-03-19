# reNgine-ng Custom Configuration Repository

**Author**: pt-zenity  
**Target**: reNgine-ng v3.0.0  
**Updated**: 2026-03-19  

---

## Overview

This repository contains all custom configurations, templates, and enhancements for [reNgine-ng](https://github.com/yogeshojha/rengine) — a fully automated reconnaissance framework for bug bounty and penetration testing.

### What's included

| Directory | Description |
|-----------|-------------|
| `custom-css-v3/` | Professional dark-mode CSS theme v3.0.0 |
| `custom-nuclei-templates/` | 29 custom Nuclei detection templates |
| `fast-scan-engines/` | 5 optimised speed-focused scan engine configs |
| `rengine-patches/` | Misc patches and deploy helpers |
| `rengine-deploy/` | Deployment scripts |

---

## 1. Custom CSS Theme (v3.0.0)

### File
`custom-css-v3/custom.css` — 1,765 lines, ~60 KB

### Features
- Animated mesh gradient background
- Glassmorphism navbar (`backdrop-filter: blur(24px) saturate(160%)`)
- Enhanced card accents and hover glows
- Shimmer button overlay
- Modal scaling animation
- Progress-bar shimmer
- Dropdown fade-in
- Severity-based row tints
- New `.card-glass` variant
- Helper classes: `.glow-green`, `.glow-blue`, `.shadow`
- Dark-mode SweetAlert2 overrides
- Transparent scrollbar track
- Gradient underline for page titles
- 992 px responsive breakpoint

### Deploy

```bash
# Copy to reNgine web static
sudo cp custom-css-v3/custom.css /home/rengine/rengine-ng/web/static/custom/custom.css
sudo cp custom-css-v3/custom.css /home/rengine/rengine-ng/web/staticfiles/custom/custom.css

# Copy into running container
docker cp custom-css-v3/custom.css rengine-web-1:/home/rengine/rengine/static/custom/custom.css
docker cp custom-css-v3/custom.css rengine-web-1:/home/rengine/rengine/staticfiles/custom/custom.css
```

---

## 2. Custom Nuclei Templates (29 templates)

### Categories

#### Next.js (7 templates)
| Template | Severity | Description |
|----------|----------|-------------|
| `CVE-2025-29927-enhanced.yaml` | CRITICAL | Next.js Middleware Authorization Bypass |
| `CVE-2024-34351-nextjs-ssrf.yaml` | HIGH | Next.js Host Header SSRF |
| `nextjs-api-routes-enum.yaml` | MEDIUM | API route enumeration |
| `nextjs-debug-page.yaml` | MEDIUM | Debug page exposure |
| `nextjs-env-exposure.yaml` | MEDIUM | Environment variable leakage |
| `nextjs-open-redirect.yaml` | MEDIUM | Open redirect via `_next/image` |
| `nextjs-source-map-exposure.yaml` | HIGH | Source map file exposure |

#### Laravel (6 templates)
| Template | Severity | Description |
|----------|----------|-------------|
| `laravel-debug-rce-chain.yaml` | CRITICAL | Debug mode RCE chain detection |
| `laravel-env-exposure-extended.yaml` | CRITICAL | `.env` file exposure (extended paths) |
| `laravel-horizon-unauth.yaml` | HIGH | Laravel Horizon dashboard unauth access |
| `laravel-routes-exposure.yaml` | MEDIUM | Route listing exposure |
| `laravel-storage-link-exposure.yaml` | HIGH | Storage link directory traversal |
| `laravel-telescope-unauth.yaml` | HIGH | Laravel Telescope unauth access |

#### Livewire (3 templates)
| Template | Severity | Description |
|----------|----------|-------------|
| `CVE-2025-54068-livewire-upload-rce.yaml` | CRITICAL | Livewire file upload RCE |
| `livewire-component-exposure.yaml` | MEDIUM | Component endpoint exposure |
| `livewire-ssrf-component.yaml` | HIGH | SSRF via Livewire component render |

#### Swagger / API (3 templates)
| Template | Severity | Description |
|----------|----------|-------------|
| `swagger-ui-exposure.yaml` | MEDIUM | Swagger UI public exposure |
| `swagger-api-auth-bypass.yaml` | HIGH | Swagger API authentication bypass |
| `graphql-introspection.yaml` | MEDIUM | GraphQL introspection enabled |

#### React (3 templates)
| Template | Severity | Description |
|----------|----------|-------------|
| `react-devtools-exposure.yaml` | MEDIUM | React DevTools exposed in production |
| `react-redux-state-exposure.yaml` | HIGH | Redux state exposed in response |
| `react-xss-injection.yaml` | HIGH | `dangerouslySetInnerHTML` XSS vector |

#### Generic (7 templates)
| Template | Severity | Description |
|----------|----------|-------------|
| `backup-file-exposure.yaml` | HIGH | Backup file / archive exposure |
| `cloud-metadata-ssrf.yaml` | CRITICAL | AWS/GCP/Azure metadata SSRF |
| `cors-misconfiguration.yaml` | HIGH | CORS wildcard misconfiguration |
| `firebase-exposure.yaml` | CRITICAL | Firebase database public exposure |
| `git-exposure.yaml` | HIGH | `.git` directory exposure |
| `js-api-key-leak.yaml` | HIGH | API key leak in JavaScript files |
| `jwt-none-algorithm.yaml` | CRITICAL | JWT "none" algorithm bypass |

### Deploy to reNgine

```bash
# Copy into celery container (where Nuclei runs)
docker cp custom-nuclei-templates/. rengine-celery-1:/home/rengine/nuclei-templates/http/custom/

# Verify
docker exec rengine-celery-1 find /home/rengine/nuclei-templates/http/custom -name "*.yaml" | wc -l
# Expected: 29

# Validate all templates
docker exec rengine-celery-1 bash -c "nuclei -validate -t /home/rengine/nuclei-templates/http/custom/ 2>&1 | tail -5"

# Copy to Docker volume for persistence
docker run --rm \
  -v rengine_nuclei_templates:/nuclei \
  -v /home/rengine/webapp/custom-nuclei-templates:/src:ro \
  alpine sh -c "mkdir -p /nuclei/http/custom && cp -r /src/. /nuclei/http/custom/"
```

### Use in Scan Engine YAML

Add the custom template paths to any scan engine `vulnerability_scan` block:

```yaml
vulnerability_scan:
  run_nuclei: true
  custom_templates:
    - http/custom/nextjs/CVE-2025-29927-enhanced.yaml
    - http/custom/nextjs/CVE-2024-34351-nextjs-ssrf.yaml
    - http/custom/nextjs/nextjs-source-map-exposure.yaml
    - http/custom/laravel/laravel-debug-rce-chain.yaml
    - http/custom/laravel/laravel-env-exposure-extended.yaml
    - http/custom/livewire/CVE-2025-54068-livewire-upload-rce.yaml
    - http/custom/swagger/swagger-api-auth-bypass.yaml
    - http/custom/generic/jwt-none-algorithm.yaml
    - http/custom/generic/cloud-metadata-ssrf.yaml
    - http/custom/generic/firebase-exposure.yaml
  severities:
    - unknown
    - info
    - low
    - medium
    - high
    - critical
```

---

## 3. Fast Scan Engines (IDs 18–22)

Five optimised scan engines added to the reNgine database:

| ID | Name | Use Case | Est. Time | Threads | Rate |
|----|------|----------|-----------|---------|------|
| 18 | Fast - Lightning Recon | Subdomain discovery only | 3–5 min | 50 | 300/s |
| 19 | Fast - Quick Vuln (High+Critical) | Critical vuln check | 5–10 min | 80 | 300/s |
| 20 | Fast - Speed Bug Bounty (Full) | Full bug bounty pipeline | 15–25 min | 50 | 250/s |
| 21 | Fast - Ultra Port Scan (top100) | Fast port scan | 2–5 min | 100 | 500/s |
| 22 | Fast - Subdomain + Screenshot | Visual recon | 8–12 min | 50 | 200/s |

### Speed vs. Default Comparison

| Parameter | Default Engine | Fast Engines |
|-----------|---------------|--------------|
| Threads | 30 | 50–100 |
| Timeout | 5 s | 3–4 s |
| Rate limit | 150 req/s | 200–500 req/s |
| Retries | 1 | 0 |
| Subdomain tools | 6 (all) | 3 (subfinder, ctfr, tlsx) |
| Nuclei scope | All severities | Medium–Critical only |
| Pre-crawl batch | default | 500 |

### Custom Scan Engines with Full Stack Templates (IDs 23–26)

| ID | Name | Templates Used |
|----|------|---------------|
| 23 | Custom Full Stack CVE Scanner | All 29 custom templates |
| 24 | Custom Laravel+Livewire Deep Scan | Laravel + Livewire templates |
| 25 | Custom Next.js+React Security Audit | Next.js + React templates |
| 26 | Custom API Security (Swagger+GraphQL+JWT) | Swagger + generic auth templates |

### Reinstall Engines after DB Reset

```bash
# Fast engines
docker cp fast-scan-engines/insert_engines.sql rengine-db-1:/tmp/
docker exec rengine-db-1 sh -c 'psql -U rengine -d rengine -f /tmp/insert_engines.sql'

# Custom template engines
docker cp fast-scan-engines/insert_custom_engines.sql rengine-db-1:/tmp/
docker exec rengine-db-1 sh -c 'psql -U rengine -d rengine -f /tmp/insert_custom_engines.sql'
```

---

## 4. Complete Reinstall (from scratch)

If reNgine is re-deployed, run this to restore everything:

```bash
# 1. Deploy CSS theme
sudo cp custom-css-v3/custom.css /path/to/rengine-ng/web/static/custom/custom.css
docker cp custom-css-v3/custom.css rengine-web-1:/home/rengine/rengine/staticfiles/custom/custom.css

# 2. Deploy Nuclei templates
docker cp custom-nuclei-templates/. rengine-celery-1:/home/rengine/nuclei-templates/http/custom/
docker run --rm \
  -v rengine_nuclei_templates:/nuclei \
  -v $(pwd)/custom-nuclei-templates:/src:ro \
  alpine sh -c "mkdir -p /nuclei/http/custom && cp -r /src/. /nuclei/http/custom/"

# 3. Insert scan engines
docker cp fast-scan-engines/insert_engines.sql rengine-db-1:/tmp/
docker exec rengine-db-1 sh -c 'psql -U rengine -d rengine -f /tmp/insert_engines.sql'
```

---

## 5. Live Test Results

Tested against `https://103.253.24.121` (reNgine-ng self-hosted instance):

| Finding | Severity | Template |
|---------|----------|----------|
| Open redirect via `/_next/image` | MEDIUM | nextjs-open-redirect |
| Open redirect via `/?redirect=` | MEDIUM | nextjs-open-redirect |
| Swagger UI exposed at `/swagger-ui` | MEDIUM | swagger-ui-exposure |
| Swagger UI exposed at `/api/swagger.json` | MEDIUM | swagger-ui-exposure |
| Swagger UI exposed at `/api-docs/swagger.json` | MEDIUM | swagger-ui-exposure |

Total: **10 findings** from 224 requests (98–100% success rate)

---

## Repository Structure

```
.
├── README.md                          # This file
├── custom-css-v3/
│   └── custom.css                     # v3.0.0 professional dark theme
├── custom-nuclei-templates/
│   ├── generic/                       # 7 generic detection templates
│   ├── laravel/                       # 6 Laravel-specific templates
│   ├── livewire/                      # 3 Livewire templates
│   ├── nextjs/                        # 7 Next.js templates
│   ├── react/                         # 3 React templates
│   └── swagger/                       # 3 Swagger/API templates
├── fast-scan-engines/
│   ├── README.md                      # Engine documentation
│   ├── insert_engines.sql             # SQL to restore fast engines
│   ├── fast_lightningrecon.yaml       # Engine 18 config
│   ├── fast_quickvuln_high_critical_.yaml  # Engine 19 config
│   ├── fast_speedbugbounty_full_.yaml # Engine 20 config
│   ├── fast_ultraportscan_top100_.yaml # Engine 21 config
│   └── fast_subdomain_screenshot.yaml # Engine 22 config
└── rengine-patches/
    └── ...                            # Additional patches
```

---

## License

MIT License — free to use, modify, and distribute.  
Attribution appreciated: **pt-zenity**
