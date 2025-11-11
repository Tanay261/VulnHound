# vulnhound/scanner.py
import asyncio
import json
import re
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

import httpx
from tenacity import retry, wait_exponential, stop_after_attempt

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
SONAR_URL = "https://sonar.omnisint.io/subdomains/{domain}"
HTTP_TIMEOUT = 12.0
USER_AGENT = "VulnHound/0.3 (+https://github.com/you/vulnhound)"
MAX_CONCURRENT = 10
REQUEST_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT)

# basic tech heuristics
TECH_RULES = {
    "nginx": lambda headers, body: "nginx" in (headers.get("server") or "").lower(),
    "apache": lambda headers, body: ("apache" in (headers.get("server") or "").lower()) or ("httpd" in (headers.get("server") or "").lower()),
    "microsoft iis": lambda headers, body: "iis" in (headers.get("server") or "").lower(),
    "wordpress": lambda headers, body: "wp-content" in (body or ""),
    "php": lambda headers, body: "php" in (headers.get("x-powered-by") or "").lower(),
}

def _debug(msg: str):
    # simple debug sink; can be swapped for logging
    print(f"[VulnHound] {msg}")

@retry(wait=wait_exponential(multiplier=0.5, min=1, max=8), stop=stop_after_attempt(3))
async def _http_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    return await client.get(url, **kwargs)

def _normalize_candidate(s: str) -> str:
    """
    Turn crt.sh / sonar entries into a clean host string.
    Examples:
      "http://example.com/path" -> "example.com"
      "example.com" -> "example.com"
      "https://sub.example.com:8443/" -> "sub.example.com:8443"
      "sub.example.com/#/foo" -> "sub.example.com"
    """
    if not s:
        return s
    s = s.strip()
    # If it already looks like a bare hostname, return as-is (no scheme, no path)
    # But if it contains a scheme or slash, parse
    if s.startswith("http://") or s.startswith("https://") or "/" in s or ":" in s:
        try:
            p = urlparse(s)
            host = p.netloc or p.path  # sometimes urlparse on "example.com" yields path
            # strip credentials if any
            if "@" in host:
                host = host.split("@", 1)[1]
            # strip trailing colon or slashes
            host = host.rstrip("/").strip()
            return host
        except Exception:
            return s
    return s

async def query_crtsh(domain: str, limit: Optional[int] = 500) -> List[str]:
    url = CRT_SH_URL.format(domain=domain)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
        try:
            r = await _http_get(client, url)
            entries = r.json() if r.status_code == 200 else []
        except Exception as e:
            _debug(f"crt.sh fetch error: {e}")
            entries = []
    subs = set()
    for e in entries:
        name = (e.get("name_value") or "").strip()
        for n in name.split("\n"):
            n = n.strip()
            if n and n.endswith(domain):
                subs.add(_normalize_candidate(n).lstrip("*."))
    out = sorted(subs)
    if limit:
        out = out[:limit]
    _debug(f"crt.sh returned {len(out)} entries")
    return out

async def query_sonar(domain: str, limit: Optional[int] = 500) -> List[str]:
    url = SONAR_URL.format(domain=domain)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
        try:
            r = await _http_get(client, url)
            data = r.json() if r.status_code == 200 else []
            if isinstance(data, list):
                out = sorted(set(_normalize_candidate(s) for s in data if s.endswith(domain)))
                if limit:
                    out = out[:limit]
                _debug(f"sonar returned {len(out)} entries")
                return out
        except Exception as e:
            _debug(f"sonar fetch error: {e}")
    return []

async def fingerprint_host(host: str) -> Dict[str, Any]:
    """
    host is expected as a hostname or host:port (no scheme, path, or fragment)
    """
    async with REQUEST_SEMAPHORE:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
            error = None
            r = None
            tried = []
            # Build candidate URLs from host (prefer https then http)
            candidates = [f"https://{host}", f"http://{host}"]
            for url in candidates:
                tried.append(url)
                try:
                    r = await _http_get(client, url, verify=True)
                    break
                except httpx.RequestError as e:
                    error = str(e)
                    # try again with verify=False if it's a TLS issue
                    if isinstance(e, httpx.ConnectError) or isinstance(e, httpx.ReadTimeout):
                        # fallback to insecure TLS only as last resort
                        try:
                            r = await client.get(url, verify=False)
                            break
                        except Exception:
                            r = None
                    r = None
                except Exception as e:
                    error = str(e)
                    r = None

            if not r:
                _debug(f"failed to fetch {host}. tried: {tried} error: {error}")
                return {"host": host, "up": False, "error": error}

            # Build base URL properly from r.url
            try:
                scheme = r.url.scheme
                host_part = r.url.host
                port = r.url.port
                base = f"{scheme}://{host_part}" + (f":{port}" if port else "")
            except Exception:
                base = f"{r.url}"

            headers = {k.lower(): v for k, v in r.headers.items()}
            title = ""
            try:
                m = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
                if m:
                    title = m.group(1).strip()
            except Exception:
                title = ""

            detected = []
            for name, fn in TECH_RULES.items():
                try:
                    if fn(headers, r.text):
                        detected.append(name)
                except Exception:
                    continue

            return {
                "host": host,
                "up": True,
                "status_code": getattr(r, "status_code", None),
                "server_header": headers.get("server"),
                "x_powered_by": headers.get("x-powered-by"),
                "title": title,
                "technologies": detected,
                "url": str(r.url),
            }

async def gather_fingerprints(hosts: List[str]) -> List[Dict[str, Any]]:
    # ensure hosts are normalized and unique
    clean = []
    for h in hosts:
        nh = _normalize_candidate(h)
        if nh and nh not in clean:
            clean.append(nh)
    tasks = [asyncio.create_task(fingerprint_host(h)) for h in clean]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return results

def save_result(scan_id: str, result: Dict[str, Any]) -> Path:
    p = DATA_DIR / f"{scan_id}.json"
    p.write_text(json.dumps(result, indent=2))
    return p

async def run_scan(domain: str, sub_limit: int = 200) -> Dict[str, Any]:
    scan_id = uuid.uuid4().hex[:12]
    result = {"scan_id": scan_id, "domain": domain, "subdomains": [], "fingerprints": [], "cves": {}, "status": "running"}

    # Query passive sources in parallel
    crt_task = asyncio.create_task(query_crtsh(domain, limit=sub_limit))
    sonar_task = asyncio.create_task(query_sonar(domain, limit=sub_limit))
    subs_crt, subs_sonar = await asyncio.gather(crt_task, sonar_task)

    # normalize + include apex domain
    subs = sorted(set(subs_crt) | set(subs_sonar) | {_normalize_candidate(domain)})
    result["subdomains"] = subs
    _debug(f"total unique targets: {len(subs)}")
    save_result(scan_id, result)

    # fingerprint first N
    targets = subs[:50]
    fingerprints = await gather_fingerprints(targets)
    result["fingerprints"] = fingerprints
    result["status"] = "fingerprinted"
    save_result(scan_id, result)
    return result
