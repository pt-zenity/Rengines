-- Engine 1: Lightning Fast Recon
INSERT INTO "scanEngine_enginetype" (engine_name, yaml_configuration, default_engine, scan_type)
VALUES (
  'Fast - Lightning Recon',
  '# ============================================================
#  LIGHTNING FAST RECON  -- pt-zenity
#  Subdomain discovery + live check dalam <5 menit
#  Tools: subfinder + ctfr + tlsx + httpx ONLY
#  Threads: 50 | Timeout: 4s | Rate: 300/s
# ============================================================

scan_type: ''bug_bounty''
timeout: 4
threads: 50
rate_limit: 300

custom_header: {
  ''User-Agent'': ''Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0'',
}

subdomain_discovery: {
  ''uses_tools'': [''subfinder'', ''ctfr'', ''tlsx''],
  ''threads'': 50,
  ''timeout'': 4,
}

http_crawl: {
  ''threads'': 50,
  ''precrawl_batch_size'': 500,
}',
  false,
  'bug_bounty'
);

-- Engine 2: Quick Vuln Scanner
INSERT INTO "scanEngine_enginetype" (engine_name, yaml_configuration, default_engine, scan_type)
VALUES (
  'Fast - Quick Vuln (High+Critical)',
  '# ============================================================
#  QUICK VULN SCANNER  -- pt-zenity
#  Nuclei only: High + Critical severities
#  Concurrency: 100 | Rate: 300/s | No retries
#  Gunakan sbg subscan setelah subdomain diketahui
# ============================================================

scan_type: ''bug_bounty''
timeout: 4
threads: 80
rate_limit: 300

custom_header: {
  ''User-Agent'': ''Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0'',
}

http_crawl: {
  ''threads'': 80,
}

vulnerability_scan: {
  ''run_nuclei'': true,
  ''run_dalfox'': false,
  ''run_crlfuzz'': false,
  ''run_s3scanner'': false,
  ''concurrency'': 100,
  ''intensity'': ''normal'',
  ''rate_limit'': 300,
  ''retries'': 0,
  ''timeout'': 4,
  ''fetch_llm_report'': false,
  ''nuclei'': {
    ''use_nuclei_config'': false,
    ''severities'': [''high'', ''critical''],
  }
}',
  false,
  'bug_bounty'
);

-- Engine 3: Speed Bug Bounty Full Pipeline
INSERT INTO "scanEngine_enginetype" (engine_name, yaml_configuration, default_engine, scan_type)
VALUES (
  'Fast - Speed Bug Bounty (Full)',
  '# ============================================================
#  SPEED BUG BOUNTY FULL PIPELINE  -- pt-zenity
#  Recon + Crawl + Port (top10) + Nuclei Medium-Critical
#  2-3x lebih cepat dari Initial Scan - reNgine recommended
#  Threads: 50 | Rate: 250/s | Timeout: 4s | Retries: 0
# ============================================================

scan_type: ''bug_bounty''
timeout: 4
threads: 50
rate_limit: 250

custom_header: {
  ''User-Agent'': ''Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0'',
}

subdomain_discovery: {
  ''uses_tools'': [''subfinder'', ''ctfr'', ''tlsx''],
  ''threads'': 50,
  ''timeout'': 4,
}

http_crawl: {
  ''threads'': 50,
  ''precrawl_batch_size'': 500,
}

port_scan: {
  ''timeout'': 3,
  ''ports'': [''top-10''],
  ''rate_limit'': 250,
  ''threads'': 50,
  ''passive'': false,
}

fetch_url: {
  ''uses_tools'': [''katana'', ''waybackurls''],
  ''remove_duplicate_endpoints'': true,
  ''duplicate_fields'': [''content_length'', ''page_title''],
  ''gf_patterns'': [''xss'', ''sqli'', ''lfi'', ''ssrf'', ''rce'', ''redirect''],
  ''ignore_file_extensions'': [''png'', ''jpg'', ''jpeg'', ''gif'', ''mp4'', ''mpeg'', ''mp3'', ''svg'', ''ico'', ''woff'', ''woff2'', ''ttf''],
  ''threads'': 50,
}

vulnerability_scan: {
  ''run_nuclei'': true,
  ''run_dalfox'': false,
  ''run_crlfuzz'': false,
  ''run_s3scanner'': false,
  ''concurrency'': 80,
  ''intensity'': ''normal'',
  ''rate_limit'': 250,
  ''retries'': 0,
  ''timeout'': 4,
  ''fetch_llm_report'': false,
  ''nuclei'': {
    ''use_nuclei_config'': false,
    ''severities'': [''medium'', ''high'', ''critical''],
  }
}',
  false,
  'bug_bounty'
);

-- Engine 4: Ultra Fast Port Scan
INSERT INTO "scanEngine_enginetype" (engine_name, yaml_configuration, default_engine, scan_type)
VALUES (
  'Fast - Ultra Port Scan (top100)',
  '# ============================================================
#  ULTRA FAST PORT SCAN  -- pt-zenity
#  Naabu top-100 ports: threads 100, rate 500/s
#  Cocok untuk IP range / internal network / asset discovery
#  Timeout: 3s | Threads: 100 | Rate: 500/s
# ============================================================

scan_type: ''bug_bounty''
timeout: 3
threads: 100
rate_limit: 500

custom_header: {
  ''User-Agent'': ''Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0'',
}

http_crawl: {
  ''threads'': 100,
}

port_scan: {
  ''timeout'': 3,
  ''ports'': [''top-100''],
  ''rate_limit'': 500,
  ''threads'': 100,
  ''passive'': false,
}',
  false,
  'bug_bounty'
);

-- Engine 5: Instant Subdomain + Screenshot
INSERT INTO "scanEngine_enginetype" (engine_name, yaml_configuration, default_engine, scan_type)
VALUES (
  'Fast - Subdomain + Screenshot',
  '# ============================================================
#  INSTANT SUBDOMAIN + SCREENSHOT  -- pt-zenity
#  Recon cepat dengan hasil visual screenshot
#  Tanpa vuln/port scan -- cocok untuk asset overview
#  Selesai dalam <10 menit untuk domain medium
# ============================================================

scan_type: ''bug_bounty''
timeout: 5
threads: 50
rate_limit: 200

custom_header: {
  ''User-Agent'': ''Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0'',
}

subdomain_discovery: {
  ''uses_tools'': [''subfinder'', ''ctfr'', ''tlsx''],
  ''threads'': 50,
  ''timeout'': 5,
}

http_crawl: {
  ''threads'': 50,
  ''precrawl_batch_size'': 400,
}

screenshot: {
  ''intensity'': ''normal'',
  ''timeout'': 8,
  ''threads'': 50,
}',
  false,
  'bug_bounty'
);
