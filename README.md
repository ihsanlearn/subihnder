# subihnder.py  
High-Performance Asynchronous Subdomain Enumeration Toolkit  
Single-file, fast, extensive, and designed for serious recon workflows.

---

## Overview

`subihnder.py` is a high-performance passive subdomain enumeration tool written in Python 3.10+.  
It focuses on:

- High-speed asynchronous operations (asyncio + aiohttp)  
- Multi-source aggregation  
- Relaxed-but-robust error handling  
- Subdomain normalization and validation  
- Clean, single-file final output (`subdomains.txt`)  

It is built for cybersecurity research, OSINT, reconnaissance, and infrastructure mapping — only for **legal and authorized usage**.

---

## Features

### Asynchronous Engine
- Fully asynchronous with connection pooling  
- Built on `aiohttp` and `asyncio`  
- Per-source timeouts and retry logic  

### Multi-Source Passive Enumeration
Includes the following providers:

- crt.sh  
- AlienVault OTX  
- urlscan.io  
- Wayback Machine (CDX API)  
- Subfinder (optional, if installed)  
- Assetfinder (optional, if installed)

### Smart Caching System
- Cache stored in `~/.cache/subihnder/`  
- Optional flags:  
  - `--no-cache` (disable cache completely)  
  - `--refresh` (force refresh per-domain)

### Intelligent Normalization
- Removes wildcards (`*.example.com`)  
- Extracts hostnames from URLs  
- Lowercase enforcement  
- Regex-based validation  
- Deduplication across all sources

### Optimized Runtime Output
- Structured progress indicators  
- Completion badges per source  
- Summary and unique count  
- Clean logging separation from final output

### Clean Final Output
Results always end in:

```
subdomains.txt
```

Contains deduplicated, sanitized, sorted subdomains.

---

## Installation

### 1. Clone Repository

```
git clone https://github.com/<yourusername>/subihnder
cd subihnder
```

### 2. Install Python Dependencies

Use:

```
pip install -r requirements.txt
```

Or manually:

```
pip install aiohttp aiodns tldextract colorama rich
```

(“rich” is optional but recommended for improved console UI.)

### 3. Optional External Tools

If installed, they will be auto-detected:

- subfinder  
- assetfinder  

They are not required, but useful for extended enumeration.

---

## Usage

### Enumerate a Single Domain

```
python3 subihnder.py -d example.com
```

### Read Domains from List File

```
python3 subihnder.py -l domains.txt
```

### Increase Concurrency (default = 50)

```
python3 subihnder.py -d example.com -p 200
```

### Disable Cache

```
python3 subihnder.py -d example.com --no-cache
```

### Force Refresh Cache

```
python3 subihnder.py -d example.com --refresh
```

### Custom Output Filename

```
python3 subihnder.py -d example.com -o results.txt
```

---

## Example Output (Runtime)

```
[CRT]        ✔ 94 found
[OTX]        ✔ 41 found
[URLSCAN]    ✔ 66 found
[WAYBACK]    ✔ 120 found
[SUBFINDER]  ✔ 38 found
---------------------------------------
[MERGE]      185 unique subdomains
```

The final file:

```
subdomains.txt
```

Example content:

```
api.example.com
dev.example.com
cdn.example.com
m.example.com
static.example.com
```

---

## Directory Structure

```
subihnder/
│
├── subihnder.py
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.10 or newer  
- Internet connection  
- (Optional) subfinder, assetfinder  

---

## Legal Notice

This tool is intended exclusively for:

- lawful cybersecurity testing  
- internal security audits  
- OSINT research  
- penetration testing **with explicit permission**  
- experimentation within your own environment  

Unauthorized scanning of external infrastructure is illegal.

---

## License

MIT License — free to modify, fork, and enhance.

---

## Author

Made by iihn for ethical cybersecurity research and tooling development.  
Contributions are welcome.

