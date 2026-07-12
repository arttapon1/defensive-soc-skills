#!/usr/bin/env python3
"""
respond_block.py — reference containment client for SOAR playbooks.

Blocks (or unblocks) an indicator on a firewall/WAF via API. Safety-first:
  * DRY-RUN BY DEFAULT. It prints the exact request it *would* send and exits.
    Nothing is changed unless you pass --commit.
  * Enforces a never-block allowlist (RFC1918 + your corp ranges).
  * Requires credentials from environment variables — never hardcoded.
  * Supports rollback via --action unblock.

Stdlib only. Only operate against infrastructure you are authorized to control.

Supported (reference) integrations: cloudflare, paloalto, fortinet, crowdstrike.
Extend `INTEGRATIONS` for Check Point, F5, AWS WAF, etc.

Usage:
    # dry-run (safe, default)
    python3 respond_block.py --integration cloudflare --action block --indicator 203.0.113.10
    # actually apply
    export CF_API_TOKEN=...; export CF_ZONE=...
    python3 respond_block.py --integration cloudflare --action block \
        --indicator 203.0.113.10 --ttl 24h --commit
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.request
import urllib.error

NEVER_BLOCK = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16",
    # add corp/partner/monitoring ranges here
]


def is_allowlisted(indicator: str) -> bool:
    try:
        ip = ipaddress.ip_address(indicator)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(n) for n in NEVER_BLOCK)


def http(method, url, headers, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("replace") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("replace")[:300]}
    except Exception as e:  # noqa: BLE001
        return 0, {"error": str(e)}


# --- integration request builders -------------------------------------------
# Each returns (description, method, url, headers, body) WITHOUT sending.

def cloudflare(action, indicator, ttl):
    token = os.getenv("CF_API_TOKEN", "<CF_API_TOKEN>")
    zone = os.getenv("CF_ZONE", "<CF_ZONE>")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone}/firewall/access_rules/rules"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    mode = "block" if action == "block" else "whitelist"
    body = {"mode": mode, "configuration": {"target": "ip", "value": indicator},
            "notes": f"SOAR auto-{action} ttl={ttl}"}
    return (f"Cloudflare IP access rule: {mode} {indicator}",
            "POST", url, headers, body)


def paloalto(action, indicator, ttl):
    key = os.getenv("PANOS_API_KEY", "<PANOS_API_KEY>")
    host = os.getenv("PANOS_HOST", "<PANOS_HOST>")
    # Prefer a Dynamic Address Group registration (no commit needed).
    op = "register" if action == "block" else "unregister"
    url = f"https://{host}/api/?type=user-id&key={key}"
    xml = (f"<uid-message><type>update</type><payload><{op}>"
           f"<entry ip=\"{indicator}\"><tag><member>soar_blocklist</member></tag></entry>"
           f"</{op}></payload></uid-message>")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    return (f"PAN-OS DAG {op} {indicator} -> tag soar_blocklist (ttl {ttl})",
            "POST", url, headers, {"cmd": xml})


def fortinet(action, indicator, ttl):
    token = os.getenv("FORTI_API_TOKEN", "<FORTI_API_TOKEN>")
    host = os.getenv("FORTI_HOST", "<FORTI_HOST>")
    name = f"soar_block_{indicator}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if action == "block":
        # Create a firewall address object. To actually deny traffic, reference it
        # from a deny policy or add it to the 'soar_blocklist' address group.
        url = f"https://{host}/api/v2/cmdb/firewall/address"
        body = {"name": name, "subnet": f"{indicator} 255.255.255.255",
                "comment": f"SOAR auto-block ttl={ttl}"}
        return (f"FortiGate create address object {name} ({indicator}) "
                f"— bind to deny policy / soar_blocklist group",
                "POST", url, headers, body)
    url = f"https://{host}/api/v2/cmdb/firewall/address/{name}"
    return (f"FortiGate delete address object {name}", "DELETE", url, headers, None)


def _falcon_ioc_type(indicator: str) -> str:
    try:
        ipaddress.ip_address(indicator)
        return "ipv4" if ":" not in indicator else "ipv6"
    except ValueError:
        pass
    h = indicator.strip().lower()
    if len(h) == 32 and all(c in "0123456789abcdef" for c in h):
        return "md5"
    if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
        return "sha256"
    return "domain"


def crowdstrike(action, indicator, ttl):
    # CrowdStrike Falcon custom IOC management. FALCON_TOKEN must be a bearer token
    # already obtained from the /oauth2/token endpoint (client_id + secret).
    token = os.getenv("FALCON_TOKEN", "<FALCON_TOKEN>")
    base = os.getenv("FALCON_CLOUD", "api.crowdstrike.com")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    itype = _falcon_ioc_type(indicator)
    if action == "block":
        url = f"https://{base}/iocs/entities/indicators/v1"
        body = {"indicators": [{
            "type": itype, "value": indicator, "action": "prevent",
            "severity": "high", "platforms": ["windows", "mac", "linux"],
            "applied_globally": True,
            "description": f"SOAR auto-block ttl={ttl}",
        }]}
        return (f"CrowdStrike add custom IOC {itype}:{indicator} action=prevent",
                "POST", url, headers, body)
    # Unblock: delete by filter (resolving the IOC id happens server-side).
    url = f"https://{base}/iocs/entities/indicators/v1?filter=value:'{indicator}'"
    return (f"CrowdStrike remove custom IOC {indicator}", "DELETE", url, headers, None)


INTEGRATIONS = {"cloudflare": cloudflare, "paloalto": paloalto,
                "fortinet": fortinet, "crowdstrike": crowdstrike}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--integration", required=True, choices=sorted(INTEGRATIONS))
    ap.add_argument("--action", required=True, choices=("block", "unblock"))
    ap.add_argument("--indicator", required=True)
    ap.add_argument("--ttl", default="24h", help="informational; enforce expiry in your platform")
    ap.add_argument("--commit", action="store_true",
                    help="actually send the request (default: dry-run)")
    args = ap.parse_args()

    if args.action == "block" and is_allowlisted(args.indicator):
        sys.exit(f"REFUSED: {args.indicator} is in the never-block allowlist.")

    desc, method, url, headers, body = INTEGRATIONS[args.integration](
        args.action, args.indicator, args.ttl)

    print(f"Integration : {args.integration}")
    print(f"Action      : {args.action}")
    print(f"Plan        : {desc}")
    print(f"Request     : {method} {url}")
    print(f"Body        : {json.dumps(body)[:400]}")

    if not args.commit:
        print("\nDRY-RUN — nothing sent. Re-run with --commit to apply.")
        redacted = {k: ("<redacted>" if k.lower() == "authorization" else v)
                    for k, v in headers.items()}
        print(f"(headers: {redacted})")
        return

    if re.search(r"<[A-Z0-9_]+>", url + json.dumps(headers)):
        sys.exit("REFUSED: credentials not set in environment. See integration-catalog.md.")

    status, resp = http(method, url, headers, body)
    print(f"\nSent. HTTP {status}: {json.dumps(resp)[:400]}")
    if status and status >= 400:
        sys.exit(1)


if __name__ == "__main__":
    main()
