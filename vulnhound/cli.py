# vulnhound/cli.py
import asyncio
import json
from rich import print
from vulnhound.scanner import run_scan, save_result

def main():
    import argparse
    parser = argparse.ArgumentParser(description="VulnHound - passive recon & CVE mapper")
    parser.add_argument("--domain", required=True, help="Target domain (example.com)")
    args = parser.parse_args()

    domain = args.domain
    print(f"[bold green]Starting scan for[/] {domain}")

    # Python 3.11+ safe
    result = asyncio.run(run_scan(domain))
    scan_id = result["scan_id"]
    p = save_result(scan_id, result)

    # small summary
    fps = result.get("fingerprints", [])
    up = sum(1 for f in fps if f.get("up"))
    down = len(fps) - up
    print(f"Scan saved:[/] {p}")
    print(f"Targets:[/] {len(result.get('subdomains', []))}  "
          f"UP:[/]{up} DOWN:[/]{down}")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
