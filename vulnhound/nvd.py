# vulnhound/nvd.py
import os, asyncio, json, time, httpx, hashlib
from pathlib import Path
from typing import List, Dict

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HTTP_TIMEOUT = 15.0
NVD_API_KEY = os.getenv("NVD_API_KEY")

CACHE_DIR = Path.home()/".vulnhound"/"cache"/"nvd"; CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_TTL = 24*3600  # 1 day

def _ck(keyword:str)->Path: return CACHE_DIR/(hashlib.sha1(keyword.encode()).hexdigest()+".json")
def _read_cache(k:str):
    p=_ck(k)
    if not p.exists(): return None
    if time.time()-p.stat().st_mtime>CACHE_TTL: return None
    try: return json.loads(p.read_text())
    except Exception: return None
def _write_cache(k:str, data):
    _ck(k).write_text(json.dumps(data))

async def query_nvd_by_keyword(keyword:str, max_results:int=5)->List[Dict]:
    cached=_read_cache(keyword)
    if cached is not None: return cached
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params  = {"keywordSearch": keyword, "resultsPerPage": max_results}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=headers) as c:
        try:
            r = await c.get(NVD_BASE, params=params)
            if r.status_code==429:
                await asyncio.sleep(2); r=await c.get(NVD_BASE, params=params)
            r.raise_for_status()
            data=r.json()
            items=data.get("vulnerabilities",[]) or []
            out=[]
            for v in items:
                cve=v.get("cve") or {}
                descs=cve.get("descriptions") or []
                desc=descs[0].get("value") if descs else ""
                meta={
                    "id": cve.get("id"),
                    "description": desc,
                    "published": cve.get("published"),
                    "severity": None
                }
                metrics=cve.get("metrics") or {}
                try:
                    cvss=(metrics.get("cvssMetricV31") or metrics.get("cvssMetricV3") or [{}])[0]
                    meta["severity"]=cvss.get("cvssData",{}).get("baseScore")
                except Exception: pass
                out.append(meta)
            _write_cache(keyword, out)
            return out
        except Exception:
            return []
