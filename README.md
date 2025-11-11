# VulnHound 🐾
**Open-source passive recon & CVE mapping tool**

VulnHound automates external attack-surface analysis:
- Async subdomain discovery via crt.sh + Sonar
- Technology fingerprinting (headers + titles + favicon hashes)
- NVD API correlation for real CVEs
- FastAPI dashboard with severity charts
- CLI for quick scans
- Optional Slack alerts

## Quick start
```bash
git clone https://github.com/Tanay261/VulnHound.git
cd VulnHound
python -m venv .venv && . .venv/Scripts/activate
pip install -r requirements.txt
export NVD_API_KEY="yourkey"
uvicorn app.main:app --reload
# → open http://127.0.0.1:8000