# app/main.py
import asyncio, json, os
from pathlib import Path
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from vulnhound.scanner import run_scan, save_result, DATA_DIR
from vulnhound.nvd import query_nvd_by_keyword

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")  # optional

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
app = FastAPI(title="VulnHound Dashboard")

def derive_keywords(fps):
    kws=set()
    for fp in fps:
        if not fp.get("up"): continue
        # from detected techs
        for t in fp.get("technologies", []):
            kws.add("Apache HTTP Server" if t=="apache" else t)
        # headers/title
        sh=(fp.get("server_header") or "").lower()
        xp=(fp.get("x_powered_by") or "").lower()
        title=(fp.get("title") or "").lower()
        if "nginx" in sh: kws.add("nginx")
        if "apache" in sh or "httpd" in sh: kws.add("Apache HTTP Server")
        if "iis" in sh: kws.add("Microsoft IIS")
        if "php" in sh or "php" in xp: kws.add("PHP")
        if "wordpress" in title: kws.add("WordPress")
    return kws

async def _notify_slack(text:str):
    if not SLACK_WEBHOOK: return
    async with asyncio.Semaphore(1):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as c:
                await c.post(SLACK_WEBHOOK, json={"text": text})
        except Exception:
            pass

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    files=sorted(DATA_DIR.glob("*.json"), key=lambda p:p.stat().st_mtime, reverse=True)
    scans=[]
    for f in files:
        try:
            j=json.loads(f.read_text())
            scans.append({"id":f.stem,"domain":j.get("domain"),"status":j.get("status")})
        except Exception: continue
    return templates.TemplateResponse("index.html", {"request":request,"scans":scans})

@app.post("/scan", response_class=HTMLResponse)
async def launch_scan(request: Request, domain: str = Form(...)):
    asyncio.create_task(_run_full_scan(domain))
    return RedirectResponse("/", status_code=303)

@app.get("/scan_demo")
async def scan_demo():
    asyncio.create_task(_run_full_scan("testphp.vulnweb.com"))
    return RedirectResponse("/", status_code=303)

async def _run_full_scan(domain:str):
    res = await run_scan(domain)
    keywords = derive_keywords(res.get("fingerprints", []))
    cve_map={}
    if keywords:
        tasks=[query_nvd_by_keyword(k, max_results=3) for k in keywords]
        results=await asyncio.gather(*tasks)
        cve_map={k:r for k,r in zip(keywords, results)}
    res["cves"]=cve_map; res["status"]="done"
    save_result(res["scan_id"], res)

    # Slack alert on high severity
    high = sum(1 for lst in cve_map.values() for c in lst if (c.get("severity") or 0)>=7.0)
    if high>0:
        await _notify_slack(f"VulnHound: {domain} has {high} CVEs with CVSS >= 7.0")

@app.get("/results/{scan_id}", response_class=HTMLResponse)
def results(request: Request, scan_id: str):
    p=DATA_DIR/f"{scan_id}.json"
    if not p.exists(): return HTMLResponse(f"Result {scan_id} not found", status_code=404)
    j=json.loads(p.read_text())

    # prepare severity buckets for chart
    severities=[(c.get("severity") or 0) for lst in j.get("cves",{}).values() for c in lst]
    buckets={"Critical(9-10)":0,"High(7-8.9)":0,"Medium(4-6.9)":0,"Low(0-3.9)":0}
    for s in severities:
        if s>=9: buckets["Critical(9-10)"]+=1
        elif s>=7: buckets["High(7-8.9)"]+=1
        elif s>=4: buckets["Medium(4-6.9)"]+=1
        elif s>0: buckets["Low(0-3.9)"]+=1

    return templates.TemplateResponse("result.html", {"request":request, "result":j, "buckets":buckets})

@app.get("/raw/{scan_id}")
def raw(scan_id: str):
    p=DATA_DIR/f"{scan_id}.json"
    if not p.exists(): return {"error":"not found"}
    return FileResponse(path=str(p))

@app.get("/delete/{scan_id}")
def delete(scan_id:str):
    p=DATA_DIR/f"{scan_id}.json"
    if p.exists(): p.unlink()
    return RedirectResponse("/", status_code=303)
