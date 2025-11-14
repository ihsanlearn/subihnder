#!/usr/bin/env python3
"""
subihnder.py - Super-powered single-file subdomain enumerator (async, cache, smart parser).

Features:
 - Async fetchers: crt.sh, OTX (AlienVault), urlscan.io, Wayback CDX
 - Optional: subfinder, assetfinder, shodanx (if in PATH) via subprocess
 - Concurrency control
 - Per-domain cache directory (~/.cache/subihnder)
 - Normalizer using tldextract if available, fallback to regex
 - Robust JSON/text parsing, retries, timeouts
 - Single output file: subdomains.txt (one domain per line, sorted unique)
 - Live progress summary on stderr (counts, per-domain summary)
 - CLI flags similar to original bash script

Requirements:
 - Python 3.10+
 - Recommended packages: aiohttp, aiodns (optional), tldextract, colorama
   Install via: pip install aiohttp tldextract colorama
   (aiodns speeds DNS but not required)

Usage examples:
  python3 subihnder.py example.com
  python3 subihnder.py -l domains.txt -p 20 --keep-cache
  python3 subihnder.py example.com --skip-subfinder --no-color

Author: converted for Ihsan (design + features requested)
"""
from __future__ import annotations
import argparse
import asyncio
import aiohttp
import os
import sys
import re
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Set, Dict, Iterable, Optional
import hashlib
import subprocess

# Optional imports
try:
    import tldextract
    TLD_EXTRACT_OK = True
except Exception:
    TLD_EXTRACT_OK = False

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    COLOR_OK = True
except Exception:
    COLOR_OK = False
    Fore = Style = type("X", (), {"RESET_ALL": "", "GREEN": "", "YELLOW": "", "BLUE": "", "RED": ""})()

# -------------------------
# Defaults (parity with bash)
# -------------------------
DEFAULT_CONCURRENCY = 8
DEFAULT_OUTFILE = "subdomains.txt"
DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "subihnder")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) subihnder/1.0"
DEFAULT_TIMEOUT = 20
DEFAULT_RETRIES = 3

# -------------------------
# Utilities
# -------------------------
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def colored(text: str, color: str) -> str:
    if not COLOR_OK:
        return text
    return f"{color}{text}{Style.RESET_ALL}"

def safe_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", s)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

# Normalize domain-like strings
def normalize_candidate(raw: str) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip()
    # remove surrounding quotes or angle brackets
    s = s.strip('\'"<>')
    # remove path, keep host part if it's a URL
    if "://" in s:
        try:
            # quick parse
            s = re.sub(r"^[a-z0-9+\-.]+://", "", s, flags=re.I)
            s = s.split("/", 1)[0]
        except Exception:
            pass
    # remove credentials if present
    s = re.sub(r'^[^@]+@', '', s)
    # remove port
    s = re.sub(r':\d+$', '', s)
    # strip wildcard prefix
    s = re.sub(r'^\*\.', '', s)
    # strip trailing punctuation
    s = s.rstrip('.,;:')
    s = s.lower()
    # accept only valid-looking hostnames
    if re.match(r'^[a-z0-9][a-z0-9._-]{0,254}\.[a-z]{2,63}$', s):
        return s
    # try tldextract if available
    if TLD_EXTRACT_OK:
        try:
            te = tldextract.extract(s)
            if te.suffix:
                subdomain = te.subdomain
                domain = te.domain
                suffix = te.suffix
                if domain:
                    parts = []
                    if subdomain:
                        parts.append(subdomain)
                    parts.append(domain)
                    parts.append(suffix)
                    candidate = ".".join(parts)
                    if re.match(r'^[a-z0-9][a-z0-9._-]*\.[a-z]{2,63}$', candidate):
                        return candidate
        except Exception:
            return None
    return None

# extract domains from arbitrary text (URLs, JSON fields, HTML)
DOMAIN_RE = re.compile(r'([a-z0-9][a-z0-9._-]{0,254}\.[a-z]{2,63})', re.I)

def extract_domains_from_text(text: str) -> Iterable[str]:
    for m in DOMAIN_RE.finditer(text):
        yield m.group(1).lower()

# -------------------------
# Cache engine (simple per-domain file with TTL optional)
# -------------------------
class Cache:
    def __init__(self, cache_dir: str, ttl_seconds: Optional[int] = None):
        self.cache_dir = os.path.abspath(cache_dir)
        ensure_dir(self.cache_dir)
        self.ttl = ttl_seconds

    def _path(self, domain: str) -> str:
        safe = safe_filename(domain)
        return os.path.join(self.cache_dir, f"{safe}.cache")

    def exists(self, domain: str) -> bool:
        p = self._path(domain)
        return os.path.isfile(p) and (self.ttl is None or (time.time() - os.path.getmtime(p) <= self.ttl))

    def load(self, domain: str) -> List[str]:
        p = self._path(domain)
        if not os.path.isfile(p):
            return []
        try:
            with open(p, "r", encoding="utf-8") as fh:
                return [l.strip() for l in fh if l.strip()]
        except Exception:
            return []

    def save(self, domain: str, data: Iterable[str]):
        p = self._path(domain)
        try:
            with open(p, "w", encoding="utf-8") as fh:
                for d in sorted(set(data)):
                    fh.write(d + "\n")
        except Exception:
            pass

# -------------------------
# Async HTTP client wrapper
# -------------------------
class AsyncFetcher:
    def __init__(self, concurrency: int = 20, timeout: int = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.retries = retries
        self.headers = {"User-Agent": USER_AGENT}
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(timeout=self.timeout, headers=self.headers)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._session:
            await self._session.close()

    async def get_text(self, url: str) -> Optional[str]:
        if not self._session:
            raise RuntimeError("Session not started")
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                async with self.semaphore:
                    async with self._session.get(url) as resp:
                        text = await resp.text(errors="ignore")
                        return text
            except asyncio.CancelledError:
                raise
            except Exception as e:
                last_exc = e
                await asyncio.sleep(0.2 * attempt)
                continue
        # on failure:
        return None

    async def get_json(self, url: str) -> Optional[dict]:
        if not self._session:
            raise RuntimeError("Session not started")
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                async with self.semaphore:
                    async with self._session.get(url) as resp:
                        # attempt json
                        data = await resp.json(content_type=None)
                        return data
            except asyncio.CancelledError:
                raise
            except Exception as e:
                last_exc = e
                await asyncio.sleep(0.2 * attempt)
                continue
        return None

# -------------------------
# Source fetchers
# Each returns list[str] (raw candidates)
# -------------------------
async def fetch_crtsh(fetcher: AsyncFetcher, domain: str) -> List[str]:
    # prefer JSON output
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    text = await fetcher.get_text(url)
    out = []
    if not text:
        return out
    try:
        # sometimes crt.sh returns HTML for big queries -> fallback to regex
        data = json.loads(text)
        for item in data:
            nv = item.get("name_value") or ""
            if nv:
                # name_value can contain multiple lines
                for line in nv.splitlines():
                    if line.strip():
                        out.append(line.strip())
    except Exception:
        # fallback to extracting hostnames from text
        for d in extract_domains_from_text(text):
            out.append(d)
    return out

async def fetch_otx(fetcher: AsyncFetcher, domain: str) -> List[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    text = await fetcher.get_text(url)
    out = []
    if not text:
        return out
    try:
        data = json.loads(text)
        entries = data.get("passive_dns") or []
        for e in entries:
            h = e.get("hostname") if isinstance(e, dict) else None
            if h:
                out.append(h)
    except Exception:
        for d in extract_domains_from_text(text):
            out.append(d)
    return out

async def fetch_urlscan(fetcher: AsyncFetcher, domain: str) -> List[str]:
    # Use API v1 search endpoint - size param attempt
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=500"
    data = await fetcher.get_json(url)
    out = []
    if data and isinstance(data, dict):
        # results may vary
        results = data.get("results") or []
        for r in results:
            page = r.get("page") if isinstance(r, dict) else None
            if page:
                dom = page.get("domain")
                if dom:
                    out.append(dom)
            # sometimes first-level result has 'task' or other fields containing urls
            if isinstance(r, dict):
                textrepr = json.dumps(r)
                for d in extract_domains_from_text(textrepr):
                    out.append(d)
    else:
        # fallback to text fetch
        text = await fetcher.get_text(f"https://urlscan.io/search/?q=domain:{domain}")
        if text:
            for d in extract_domains_from_text(text):
                out.append(d)
    return out

async def fetch_wayback(fetcher: AsyncFetcher, domain: str) -> List[str]:
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
    text = await fetcher.get_text(url)
    out = []
    if not text:
        return out
    try:
        data = json.loads(text)
        # data[1:] contains entries where [2] often is the original URL
        for row in data[1:]:
            if isinstance(row, list) and len(row) >= 3:
                u = row[2]
                for d in extract_domains_from_text(u):
                    out.append(d)
            else:
                # fallback: stringify row
                for d in extract_domains_from_text(str(row)):
                    out.append(d)
    except Exception:
        for d in extract_domains_from_text(text):
            out.append(d)
    return out

# -------------------------
# Optional external tools runner (subfinder, assetfinder, shodanx)
# use subprocess in thread to avoid blocking event loop; returns list
# -------------------------
async def run_external_tool(cmd: List[str], label: str, tmpdir: str) -> List[str]:
    """
    Execute an external command and capture stdout lines as domain candidates.
    Non-fatal: returns empty list on failure.
    """
    try:
        # Use create_subprocess_exec to stay async
        proc = await asyncio.create_subprocess_exec(*cmd,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await proc.communicate()
        if not stdout:
            return []
        text = stdout.decode(errors="ignore")
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        return lines
    except FileNotFoundError:
        return []
    except Exception:
        return []

# -------------------------
# Orchestration per domain
# -------------------------
class Enumerator:
    def __init__(self,
                 concurrency: int = DEFAULT_CONCURRENCY,
                 cache_dir: str = DEFAULT_CACHE_DIR,
                 keep_cache: bool = False,
                 skip_subfinder: bool = False,
                 skip_assetfinder: bool = False,
                 skip_shodanx: bool = False,
                 no_color: bool = False,
                 timeout: int = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES):
        self.concurrency = concurrency
        self.cache_dir = cache_dir
        self.keep_cache = keep_cache
        self.skip_subfinder = skip_subfinder
        self.skip_assetfinder = skip_assetfinder
        self.skip_shodanx = skip_shodanx
        self.no_color = no_color
        self.timeout = timeout
        self.retries = retries

        ensure_dir(self.cache_dir)
        self.cache = Cache(self.cache_dir)
        # progress counts
        self._found_global: Set[str] = set()
        self._per_domain_counts: Dict[str, int] = {}
        self._lock = asyncio.Lock()
        # detect presence of external tools
        self.subfinder_path = shutil.which("subfinder")
        self.assetfinder_path = shutil.which("assetfinder")
        self.shodanx_path = shutil.which("shodanx")

    async def enumerate_domain(self, domain: str, fetcher: AsyncFetcher, tmpdir: str) -> List[str]:
        domain = domain.strip()
        if not domain:
            return []
        # check cache
        if self.keep_cache and self.cache.exists(domain):
            cached = self.cache.load(domain)
            await self._update_progress(domain, cached)
            return cached

        # sources tasks (curl-like/lightweight first)
        tasks = []
        tasks.append(fetch_crtsh(fetcher, domain))
        tasks.append(fetch_otx(fetcher, domain))
        tasks.append(fetch_urlscan(fetcher, domain))
        tasks.append(fetch_wayback(fetcher, domain))
        # optional heavy tools
        if (self.subfinder_path is not None) and (not self.skip_subfinder):
            sf_outfile = os.path.join(tmpdir, f"{safe_filename(domain)}.subfinder")
            # run without blocking main loop
            tasks.append(run_external_tool([self.subfinder_path, "-d", domain, "-silent"], "subfinder", tmpdir))
        if (self.assetfinder_path is not None) and (not self.skip_assetfinder):
            tasks.append(run_external_tool([self.assetfinder_path, "--subs-only", domain], "assetfinder", tmpdir))
        if (self.shodanx_path is not None) and (not self.skip_shodanx):
            tasks.append(run_external_tool([self.shodanx_path, "subdomain", "-d", domain], "shodanx", tmpdir))

        results = []
        # run concurrently and gather
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for res in gathered:
            if isinstance(res, Exception):
                continue
            if isinstance(res, list):
                for item in res:
                    if item:
                        results.append(item)
            elif isinstance(res, str):
                if res:
                    results.append(res)
        # normalize results
        normalized = set()
        for raw in results:
            # results might be JSON-ish lines or labeled lines like "[subfinder] host"
            # strip labels
            cleaned = re.sub(r'^\[[^\]]+\]\s*', '', raw).strip()
            # split if comma-separated or multiple per line
            parts = re.split(r'[\s,;]+', cleaned)
            for p in parts:
                cand = normalize_candidate(p)
                if cand and (cand.endswith("." + domain) or cand == domain):
                    normalized.add(cand)
        normalized_list = sorted(normalized)
        # save cache if requested
        if self.keep_cache and normalized_list:
            self.cache.save(domain, normalized_list)
        await self._update_progress(domain, normalized_list)
        return normalized_list

    async def _update_progress(self, domain: str, found: Iterable[str]):
        async with self._lock:
            new_count = 0
            for f in found:
                if f not in self._found_global:
                    new_count += 1
                    self._found_global.add(f)
            self._per_domain_counts[domain] = len(list(found))
            # print small live summary to stderr
            total = len(self._found_global)
            dcount = len(self._per_domain_counts)
            if self.no_color or not COLOR_OK:
                eprint(f"[*] {now_ts()} - Done {domain}: {self._per_domain_counts[domain]} found  | Total unique: {total}")
            else:
                eprint(f"{colored('[*]', Fore.BLUE)} {colored(now_ts(), Fore.YELLOW)} - {colored(domain, Fore.GREEN)}: {colored(str(self._per_domain_counts[domain]), Fore.GREEN)} found  | Total unique: {colored(str(total), Fore.GREEN)}")

# -------------------------
# CLI and main
# -------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="subihnder.py - Async, cached, smart subdomain enumeration (single-file)")
    p.add_argument("domains", nargs="*", help="one or more target domains")
    p.add_argument("-l", "--list", dest="listfile", help="file containing domains (one per line)")
    p.add_argument("-p", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="concurrency (xargs / aiohttp semaphore)")
    p.add_argument("-o", "--output", default=DEFAULT_OUTFILE, help="output filename (final merged)")
    p.add_argument("--no-cache", action="store_true", help="do not persist per-domain cache")
    p.add_argument("--keep-cache", action="store_true", help="persist per-domain cache")
    p.add_argument("--skip-subfinder", action="store_true", help="do not run subfinder external tool even if present")
    p.add_argument("--skip-assetfinder", action="store_true", help="skip assetfinder external tool")
    p.add_argument("--skip-shodanx", action="store_true", help="skip shodanx external tool")
    p.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help="cache directory")
    p.add_argument("--no-color", action="store_true", help="disable colored logs")
    p.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout seconds")
    p.add_argument("-r", "--retries", type=int, default=DEFAULT_RETRIES, help="request retries")
    return p.parse_args()

async def main_async(args: argparse.Namespace):
    # Prepare domain list
    domains: List[str] = []
    if args.listfile:
        if not os.path.isfile(args.listfile):
            eprint("[!] List file not found:", args.listfile)
            sys.exit(1)
        with open(args.listfile, "r", encoding="utf-8") as fh:
            for l in fh:
                t = l.strip()
                if t:
                    domains.append(t)
    if args.domains:
        domains.extend(args.domains)
    if not domains:
        eprint("Usage: provide at least one domain or -l listfile")
        sys.exit(1)

    # Normalize domain entries (strip scheme etc.)
    domains = [normalize_candidate(d) or d.strip().lower() for d in domains]
    domains = [d for d in domains if d]  # drop None

    # report initial config
    eprint(colored("[*] Starting ihmsubfinder (Python)", Fore.BLUE) if COLOR_OK else "[*] Starting ihmsubfinder (Python)")
    eprint(f"    Concurrency: {args.concurrency}")
    eprint(f"    Output: {args.output}")
    eprint(f"    Cache dir: {args.cache_dir}  (keep_cache={args.keep_cache})")
    eprint(f"    External tools: subfinder={'yes' if shutil.which('subfinder') else 'no'}, assetfinder={'yes' if shutil.which('assetfinder') else 'no'}, shodanx={'yes' if shutil.which('shodanx') else 'no'}")
    tmpdir = tempfile.mkdtemp(prefix="ihnsub.XXXXXX")
    ensure_dir(args.cache_dir)

    enumerator = Enumerator(concurrency=args.concurrency,
                            cache_dir=args.cache_dir,
                            keep_cache=args.keep_cache,
                            skip_subfinder=args.skip_subfinder,
                            skip_assetfinder=args.skip_assetfinder,
                            skip_shodanx=args.skip_shodanx,
                            no_color=args.no_color,
                            timeout=args.timeout,
                            retries=args.retries)

    found_global: Set[str] = set()

    try:
        async with AsyncFetcher(concurrency=args.concurrency, timeout=args.timeout, retries=args.retries) as fetcher:
            # schedule tasks for each domain with limited concurrency via semaphore
            sem = asyncio.Semaphore(args.concurrency)
            async def worker(dom: str):
                async with sem:
                    res = await enumerator.enumerate_domain(dom, fetcher, tmpdir)
                    return res
            tasks = [asyncio.create_task(worker(d)) for d in domains]
            # gather progressively
            for coro in asyncio.as_completed(tasks):
                try:
                    res: List[str] = await coro
                    for r in res:
                        found_global.add(r)
                except Exception as e:
                    eprint("[!] domain task error:", e)
    finally:
        # cleanup
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

    # Final merge + sanitize + write sorted unique
    cleaned = sorted({d.lower().strip() for d in found_global if d and re.match(r'^[a-z0-9]', d)})
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            for d in cleaned:
                fh.write(d + "\n")
    except Exception as e:
        eprint("[!] Failed to write output:", e)
        sys.exit(1)

    # Final report
    total = len(cleaned)
    eprint(colored("[✔] Done.", Fore.GREEN) if COLOR_OK else "[✔] Done.")
    eprint(f"    Total unique subdomains: {total}")
    eprint(f"    Saved to: {os.path.abspath(args.output)}")
    # optionally print sample to stderr
    if total > 0:
        eprint("    Sample (first 20):")
        for s in cleaned[:20]:
            eprint("      " + s)

def main():
    args = parse_args()
    # disable color if asked
    if args.no_color:
        global COLOR_OK
        COLOR_OK = False
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        eprint("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        eprint("[!] Fatal error:", e)
        raise

if __name__ == "__main__":
    main()
