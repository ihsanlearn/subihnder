#!/usr/bin/env bash
# ihnsubfinder.sh
# Optimized Subdomain Enumeration (crt.sh, OTX, urlscan, web.archive, subfinder, assetfinder, shodanx)

set -euo pipefail
IFS=$'\n\t'

### ===== defaults =====
CONCURRENCY=8
OUTFILE="subdomains.txt"
CACHE_DIR="${HOME}/.cache/ihnsubfinder"
TMPDIR="$(mktemp -d -t subenum.XXXXXX)"
KEEP_CACHE=false
SKIP_SUBFINDER=false
SKIP_ASSETFINDER=false
SKIP_SHODANX=false
NO_COLOR=${NO_COLOR:-false}
CURL_OPTS="--silent --show-error --fail --location --max-time 20 --retry 3 --retry-delay 2"
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) ihnsubfinder/1.0"

trap 'rm -rf "$TMPDIR"' EXIT

### ===== helpers =====
command_exists(){ command -v "$1" >/dev/null 2>&1; }
fatal(){ echo >&2 "[✖] $*"; exit 1; }
# WRITE LOGS TO STDERR so stdout stays for tool output
info(){ if [ "$NO_COLOR" = false ]; then printf "\e[1;34m[*]\e[0m %s\n" "$*" >&2; else printf "[*] %s\n" "$*" >&2; fi }
warn(){ if [ "$NO_COLOR" = false ]; then printf "\e[1;33m[!]\e[0m %s\n" "$*" >&2; else printf "[!] %s\n" "$*" >&2; fi }
ok(){ if [ "$NO_COLOR" = false ]; then printf "\e[1;32m[✔]\e[0m %s\n" "$*" >&2; else printf "[✔] %s\n" "$*" >&2; fi }

# escape domain for regex
escape_domain_for_grep(){ printf '%s' "$1" | sed 's/\./\\./g'; }

# normalize lines: remove leading *., commas -> newlines, trim, lowercase
normalize_stream(){
  sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//' \
      -e 's/^\*\.\?//' \
      -e 's/,/\n/g' \
    | tr '[:upper:]' '[:lower:]'
}

### ===== curl JSON-safe extractor (if jq available) =====
jq_ok=false
if command_exists jq; then jq_ok=true; fi

# Ensure common user bin dirs are in PATH for non-interactive shells
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"

# Properly detect tools (command_exists returns exit status only)
SUBFINDER_OK=false
ASSETFINDER_OK=false
SHODANX_OK=false
command_exists subfinder && SUBFINDER_OK=true
command_exists assetfinder && ASSETFINDER_OK=true
command_exists shodanx && SHODANX_OK=true

curl_json() {
  # usage: curl_json <url>
  curl $CURL_OPTS -A "$USER_AGENT" "$1"
}

### ===== fetchers (emit domains to stdout) =====

fetch_crtsh(){
  local domain="$1"
  local escaped
  escaped=$(escape_domain_for_grep "$domain")
  if $jq_ok; then
    curl $CURL_OPTS -A "$USER_AGENT" "https://crt.sh/?q=%25.$domain&output=json" \
      | jq -r '.[]?.name_value // empty' 2>/dev/null || true
  else
    curl $CURL_OPTS -A "$USER_AGENT" "https://crt.sh/?q=%25.$domain" \
      | grep -Eo "[A-Za-z0-9._-]+\.$domain" || true
  fi \
  | normalize_stream \
  | grep -E "\.$escaped$|^$escaped$" || true
}

fetch_otx(){
  local domain="$1"
  local escaped
  escaped=$(escape_domain_for_grep "$domain")
  if $jq_ok; then
    curl $CURL_OPTS -A "$USER_AGENT" "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" \
      | jq -r '.passive_dns[]?.hostname // empty' 2>/dev/null || true
  else
    curl $CURL_OPTS -A "$USER_AGENT" "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" \
      | grep -Eo "[A-Za-z0-9._-]+\.$domain" || true
  fi \
  | normalize_stream \
  | grep -E "^[a-z0-9]([a-z0-9._-]*[a-z0-9])?\.$escaped$" || true
}

fetch_urlscan(){
  local domain="$1"
  local escaped
  escaped=$(escape_domain_for_grep "$domain")
  if $jq_ok; then
    curl $CURL_OPTS -A "$USER_AGENT" "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" \
      | jq -r '.results[].page.domain? // empty' 2>/dev/null || true
  else
    curl $CURL_OPTS -A "$USER_AGENT" "https://urlscan.io/search/?q=domain:$domain" \
      | grep -Eo "[A-Za-z0-9._-]+\.$domain" || true
  fi \
  | normalize_stream \
  | grep -E "\.$escaped$|^$escaped$" || true
}

fetch_wayback(){
  local domain="$1"
  local escaped
  escaped=$(escape_domain_for_grep "$domain")
  if $jq_ok; then
    curl $CURL_OPTS -A "$USER_AGENT" "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=json&collapse=urlkey" \
      | jq -r '.[1:][].[2]?' 2>/dev/null || true
  else
    curl $CURL_OPTS -A "$USER_AGENT" "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=json&collapse=urlkey" \
      | grep -Eo "[A-Za-z0-9._-]+\.$domain" || true
  fi \
  | normalize_stream \
  | grep -E "\.$escaped$|^$escaped$" || true
}

# wrapper for optional tools that output domains per-line
# Use temporary output file (-o) so subfinder completes and writes fully, then cat it with label
run_subfinder(){
  local domain="$1"
  if command_exists subfinder && [ "$SKIP_SUBFINDER" = false ]; then
    info "Running Subfinder -> $(command -v subfinder)"
    local sf_tmp="$TMPDIR/${domain}.subfinder"
    # -silent prevents interactive/progress output in some versions
    subfinder -d "$domain" -all -silent -o "$sf_tmp" 2>/dev/null || true
    if [ -s "$sf_tmp" ]; then
      sed 's/^/[subfinder] /' "$sf_tmp" || true
    fi
  fi
}

run_assetfinder(){
  local domain="$1"
  if command_exists assetfinder && [ "$SKIP_ASSETFINDER" = false ]; then
    info "Running Assetfinder -> $(command -v assetfinder)"
    local af_tmp="$TMPDIR/${domain}.assetfinder"
    assetfinder --subs-only "$domain" > "$af_tmp" 2>/dev/null || true
    if [ -s "$af_tmp" ]; then
      sed 's/^/[assetfinder] /' "$af_tmp" || true
    fi
  fi
}

run_shodanx(){
  local domain="$1"
  if command_exists shodanx && [ "$SKIP_SHODANX" = false ]; then
    info "Running Shodanx -> $(command -v shodanx)"
    local sx_tmp="$TMPDIR/${domain}.shodanx"
    shodanx subdomain -d "$domain" > "$sx_tmp" 2>/dev/null || true
    if [ -s "$sx_tmp" ]; then
      sed 's/^/[shodanx] /' "$sx_tmp" || true
    fi
  fi
}

### ===== per-domain orchestration (with caching) =====
fetch_subs_for_domain(){
  local domain="$1"
  local out="$TMPDIR/${domain}.raw"
  local cache_file="$CACHE_DIR/${domain}.cache"
  mkdir -p "$CACHE_DIR"

  info "Enumerating: $domain"

  # if cache exists and not disabled, use it
  if [ -f "$cache_file" ] && [ "$KEEP_CACHE" = true ]; then
    info "Using cached results for $domain"
    cat "$cache_file" > "$out"
    return 0
  fi

  # collect: curl-based sources first (fast)
  # Append only the outputs of fetchers (info writes to stderr)
  {
    fetch_crtsh "$domain" || true
    fetch_otx "$domain" || true
    fetch_urlscan "$domain" || true
    fetch_wayback "$domain" || true
  } >> "$out" 2>/dev/null || true

  # run heavier tools sequentially per domain (safer resource use)
  # Each run_* writes labeled stdout; info prints to stderr
  {
    run_subfinder "$domain" || true
    run_assetfinder "$domain" || true
    run_shodanx "$domain" || true
  } >> "$out" 2>/dev/null || true

  # normalize and per-domain dedupe
  normalize_stream < "$out" \
    | grep -Eo "([a-z0-9._-]+\.)?$(escape_domain_for_grep "$domain")" \
    | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | sort -u > "${out}.clean"

  mv -f "${out}.clean" "$out"

  # write cache only if non-empty and caching enabled
  if [ -s "$out" ] && [ "$KEEP_CACHE" = true ]; then
    cp -f "$out" "$cache_file"
  fi

  info "Found $(wc -l < "$out" || echo 0) unique entries for $domain"
}

### ===== parse input args =====
if [ "$#" -eq 0 ]; then
  echo "Usage: $0 [-l domains.txt] [-p concurrency] [-o out.txt] [--no-cache] [--skip-subfinder] [--skip-assetfinder] [--skip-shodanx] domain..."
  exit 1
fi

# simple arg parser
DOMAINS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) shift; [ $# -gt 0 ] || fatal "Missing list file"; LISTFILE="$1"; shift
        [ -f "$LISTFILE" ] || fatal "List file not found: $LISTFILE"
        while IFS= read -r L || [ -n "$L" ]; do LTRIM="$(printf '%s' "$L" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"; [ -n "$LTRIM" ] && DOMAINS+=("$LTRIM"); done < "$LISTFILE"
        ;;
    -p) shift; [ $# -gt 0 ] || fatal "Missing concurrency value"; CONCURRENCY="$1"; shift ;;
    -o) shift; [ $# -gt 0 ] || fatal "Missing output filename"; OUTFILE="$1"; shift ;;
    --no-cache) KEEP_CACHE=false; shift ;;
    --keep-cache) KEEP_CACHE=true; shift ;;
    --skip-subfinder) SKIP_SUBFINDER=true; shift ;;
    --skip-assetfinder) SKIP_ASSETFINDER=true; shift ;;
    --skip-shodanx) SKIP_SHODANX=true; shift ;;
    --cache-dir) shift; [ $# -gt 0 ] || fatal "Missing cache dir"; CACHE_DIR="$1"; shift ;;
    --no-color) NO_COLOR=true; shift ;;
    -h|--help) echo "See top of script for usage"; exit 0 ;;
    --) shift; break ;;
    -*) fatal "Unknown option: $1" ;;
    *) DOMAINS+=("$1"); shift ;;
  esac
done

[ ${#DOMAINS[@]} -gt 0 ] || fatal "No domains provided"

info "Concurrency set to $CONCURRENCY"
info "Output file: $OUTFILE"
info "Cache dir: $CACHE_DIR (KEEP_CACHE=$KEEP_CACHE)"
info "Tools: subfinder=$SUBFINDER_OK, assetfinder=$ASSETFINDER_OK, shodanx=$SHODANX_OK, jq=$jq_ok"

### ===== run per-domain (parallelized) =====
TASKFILE="$TMPDIR/tasks.txt"
printf "%s\n" "${DOMAINS[@]}" > "$TASKFILE"

export -f fetch_crtsh fetch_otx fetch_urlscan fetch_wayback \
  run_subfinder run_assetfinder run_shodanx \
  normalize_stream escape_domain_for_grep fetch_subs_for_domain \
  command_exists fatal info warn ok

export CURL_OPTS USER_AGENT TMPDIR CACHE_DIR KEEP_CACHE \
  SKIP_SUBFINDER SKIP_ASSETFINDER SKIP_SHODANX jq_ok

info "Launching enumeration tasks..."
xargs -a "$TASKFILE" -P "$CONCURRENCY" -I{} bash -c 'fetch_subs_for_domain "$1"' _ {}

# Merge results
info "Merging results..."
cat "$TMPDIR"/*.raw 2>/dev/null | sort -u > "${OUTFILE}.tmp" || true

# Final sanitize, ensure lowercase, unique, remove blanks
sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//' "${OUTFILE}.tmp" \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E '^[a-z0-9]' \
  | sort -u > "$OUTFILE"

rm -f "${OUTFILE}.tmp"

ok "Done. Total unique subdomains: $(wc -l < "$OUTFILE" || echo 0)"
info "Saved to: $PWD/$OUTFILE"
