#!/usr/bin/env python3
"""
enrich_ioc.py — reference threat-intel enrichment client for SOAR playbooks.

Queries multiple sources for an indicator (IP / domain / hash), aggregates a
verdict, and prints JSON. Read-only: it never blocks anything. Stdlib only.

Credentials come from environment variables (see resources/integration-catalog.md):
    VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
Sources with no key are skipped gracefully, so this runs (partially) out of the box.

Usage:
    export VT_API_KEY=...; export ABUSEIPDB_API_KEY=...
    python3 enrich_ioc.py 203.0.113.10
    python3 enrich_ioc.py --type hash 44d88612fea8a8f36de82e1278abb02f
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error


def http_get(url: str, headers: dict, timeout=15):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}", "_body": e.read().decode("replace")[:200]}
    except Exception as e:  # noqa: BLE001
        return {"_error": str(e)}


def detect_type(ioc: str) -> str:
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        return "hash"
    return "domain"


def q_virustotal(ioc, ioc_type):
    key = os.getenv("VT_API_KEY")
    if not key:
        return None
    path = {"ip": f"ip_addresses/{ioc}", "domain": f"domains/{ioc}",
            "hash": f"files/{ioc}"}[ioc_type]
    data = http_get(f"https://www.virustotal.com/api/v3/{path}",
                    {"x-apikey": key})
    if "_error" in data:
        return {"source": "virustotal", "error": data["_error"]}
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    return {"source": "virustotal", "malicious": mal,
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "flag": mal > 0}


def q_abuseipdb(ioc, ioc_type):
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key or ioc_type != "ip":
        return None
    data = http_get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90",
                    {"Key": key, "Accept": "application/json"})
    if "_error" in data:
        return {"source": "abuseipdb", "error": data["_error"]}
    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    return {"source": "abuseipdb", "abuse_score": score,
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode"),
            "flag": score >= 50}


def q_otx(ioc, ioc_type):
    key = os.getenv("OTX_API_KEY")
    if not key:
        return None
    section = {"ip": f"IPv4/{ioc}", "domain": f"domain/{ioc}",
               "hash": f"file/{ioc}"}[ioc_type]
    data = http_get(f"https://otx.alienvault.com/api/v1/indicators/{section}/general",
                    {"X-OTX-API-KEY": key})
    if "_error" in data:
        return {"source": "otx", "error": data["_error"]}
    pulses = data.get("pulse_info", {}).get("count", 0)
    return {"source": "otx", "pulse_count": pulses, "flag": pulses > 0}


def q_groupib(ioc, ioc_type):
    # Group-IB Threat Intelligence is a licensed product; endpoints/auth vary by
    # contract. Wire it here once you have portal credentials (GROUPIB_API_KEY).
    if not os.getenv("GROUPIB_API_KEY"):
        return None
    return {"source": "groupib", "note": "configure endpoint per your TI contract"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("indicator")
    ap.add_argument("--type", choices=("ip", "domain", "hash"), default=None)
    ap.add_argument("--threshold", type=int, default=1,
                    help="min flagging sources to call it malicious")
    args = ap.parse_args()

    ioc_type = args.type or detect_type(args.indicator)
    results = []
    for fn in (q_virustotal, q_abuseipdb, q_otx, q_groupib):
        r = fn(args.indicator, ioc_type)
        if r is not None:
            results.append(r)

    flags = sum(1 for r in results if r.get("flag"))
    queried = [r for r in results if "error" not in r]
    verdict = ("malicious" if flags >= args.threshold
               else "suspicious" if flags > 0
               else "unknown" if not queried else "benign")

    out = {
        "indicator": args.indicator,
        "type": ioc_type,
        "sources_queried": len(results),
        "sources_flagging": flags,
        "verdict": verdict,
        "confidence": "high" if len(queried) >= 2 and flags >= 2 else
                      "medium" if flags >= 1 else "low",
        "results": results,
    }
    if not results:
        out["note"] = ("no API keys set — export VT_API_KEY / ABUSEIPDB_API_KEY / "
                       "OTX_API_KEY to enable enrichment")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
