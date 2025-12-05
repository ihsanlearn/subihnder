<div align="center">
<pre>
            ___.   .__.__                .___            
  ________ _\_ |__ |__|  |__   ____    __| _/___________ 
 /  ___/  |  \ __ \|  |  |  \ /    \  / __ |/ __ \_  __ \
 \___ \|  |  / \_\ \  |   Y  \   |  \/ /_/ \  ___/|  | \/
/____  >____/|___  /__|___|  /___|  /\____ |\___  >__|   
     \/          \/        \/     \/      \/    \/       
</pre>
</div>

<p align="center">
  <strong>High-Performance Asynchronous Subdomain Enumerator</strong>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT">
  <img src="https://img.shields.io/badge/Async-Powered-purple?style=for-the-badge&logo=python" alt="Async Powered">
</p>

<p align="center">
  A high-performance passive subdomain enumeration tool written in Python 3.10+.<br>
  It focuses on high-speed async operations, multi-source aggregation, and robust normalization.<br>
  Built for legal and authorized cybersecurity research, OSINT, and recon workflows.
</p>

---


## ✨ Features

* **🚀 High-Speed Async Engine:** Fully asynchronous using `asyncio` and `aiohttp` with connection pooling, retries, and per-source timeouts.
* **🧩 Multi-Source Aggregation:** Gathers data from numerous passive sources:
    * crt.sh (JSON)
    * AlienVault OTX
    * urlscan.io
    * Wayback Machine (CDX API)
* **🔌 External Tool Integration:** Automatically detects and uses `subfinder` and `assetfinder` (if present in `$PATH`) for expanded results.
* **🧠 Smart Caching System:** Caches per-domain results in `~/.cache/subihnder/` to speed up subsequent scans. Can be enabled with `--keep-cache`.
* **🛡️ Intelligent Normalization:** Robustly cleans and validates findings:
    * Strips wildcards (`*.example.com`)
    * Extracts hostnames from URLs and JSON blobs
    * Enforces lowercase and regex validation
    * Deduplicates all findings into one final list.
* **📊 Clean & Clear Output:** Provides live progress updates to `stderr` while writing the final, clean, sorted list to `subdomains.txt` (or a custom file).

## 🚀 Installation

### 1. Clone Repository
```bash
git clone [https://github.com/ihsanlearn/subihnder](https://github.com/ihsanlearn/subihnder)
cd subihnder
```
### 2. Install Python Dependencies
It's recommended to use a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
Install requirements:
```

```bash
pip install -r requirements.txt
```
Or manually:

```bash
pip install aiohttp tldextract colorama
```

### 3. (Optional but recommended) Install External Tools
For the best results, install these tools and ensure they are in your $PATH:
- subfinder
- assetfinder

The script will automatically detect and use them if they are available.

💻 **Usage**

Enumerate a Single Domain
```bash
python3 subihnder.py example.com
```

Enumerate Multiple Domains
```bash
python3 subihnder.py example.com another.com
```

Read Domains from a List File
```bash
python3 subihnder.py -l domains.txt
```

Increase Concurrency (Default: 8)
```bash
python3 subihnder.py -l domains.txt -p 20
```

Enable Caching
By default, the cache is not written. Use --keep-cache to save and re-use results from ~/.cache/subihnder/.
```bash
python3 subihnder.py example.com --keep-cache
```

Specify Output File
```bash
python3 subihnder.py example.com -o results.txt
```

Skip External Tools
```bash
python3 subihnder.py example.com --skip-subfinder --skip-assetfinder
```
