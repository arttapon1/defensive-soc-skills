#!/usr/bin/env python3
"""
log_timeline.py — normalize heterogeneous logs into a single, time-ordered event list.

Supports: syslog (RFC3164-ish), JSON lines, CSV (with a header), CEF, and
Apache/Nginx combined access logs. Emits a normalized CSV or JSON timeline and
records a SHA-256 of every input file for chain of custody.

Defensive/IR use only. Reads copies of evidence; never modifies inputs.

Usage:
    python3 log_timeline.py --tz +07:00 --out timeline.csv logs/*.log
    python3 log_timeline.py --format json --out timeline.json auth.json fw.csv
"""
from __future__ import annotations
import argparse
import csv
import glob
import hashlib
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta

# --- parsers -----------------------------------------------------------------

SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
CEF_RE = re.compile(r"CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|[^|]*\|"
                    r"(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|(?P<ext>.*)$")
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
SYSLOG5424_RE = re.compile(
    r"^<\d+>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?:-|\[.*?\])\s*(?P<msg>.*)$"
)
KV_RE = re.compile(r"([A-Za-z][\w.\-]*)=(\"[^\"]*\"|\[[^\]]*\]|\S+)")
MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1)}


def parse_kv(line: str):
    """Parse a key=value / logfmt line (FortiGate & many appliances)."""
    pairs = KV_RE.findall(line)
    if len(pairs) < 3:
        return None
    d = {k.lower(): v.strip('"') for k, v in pairs}
    ts = None
    if "date" in d and "time" in d:
        ts = f'{d["date"]} {d["time"]}'
    elif d.get("eventtime", "").isdigit():
        ev = int(d["eventtime"])
        if ev > 10_000_000_000_000:      # nanoseconds
            ev //= 1_000_000_000
        elif ev > 10_000_000_000:        # milliseconds
            ev //= 1000
        ts = datetime.fromtimestamp(ev, tz=timezone.utc)
    else:
        ts = d.get("timestamp") or d.get("time")
    host = d.get("devname") or d.get("hostname") or d.get("host") or ""
    actor = (d.get("srcip") or d.get("src") or d.get("srcaddr")
             or d.get("user") or "")
    return ts, host, actor


@dataclass
class Event:
    timestamp: str      # ISO 8601, tz-aware
    source_file: str
    source_type: str
    host: str
    actor: str          # ip / user / process best-effort
    message: str


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def parse_line(line: str, tz: timezone, year: int):
    line = line.rstrip("\n")
    if not line.strip():
        return None
    # JSON line
    if line.lstrip().startswith("{"):
        try:
            o = json.loads(line)
            ts = o.get("timestamp") or o.get("time") or o.get("@timestamp") or o.get("ts")
            return ("json", ts, o.get("host", ""),
                    str(o.get("src_ip") or o.get("user") or o.get("actor") or ""),
                    json.dumps(o, ensure_ascii=False))
        except json.JSONDecodeError:
            pass
    # CEF
    m = CEF_RE.search(line)
    if m:
        ext = m.group("ext")
        ts = re.search(r"(?:rt|start)=(\S+)", ext)
        src = re.search(r"src=(\S+)", ext)
        return ("cef", ts.group(1) if ts else None, m.group("product"),
                src.group(1) if src else "", m.group("name") + " | " + ext)
    # Apache/Nginx access
    m = ACCESS_RE.match(line)
    if m:
        try:
            dt = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            dt = None
        return ("access", dt, "", m.group("ip"),
                f'{m.group("req")} -> {m.group("status")}')
    # RFC5424 syslog (ISO timestamp)
    m = SYSLOG5424_RE.match(line)
    if m:
        return ("syslog5424", m.group("ts"), m.group("host"),
                m.group("app"), m.group("msg"))
    # RFC3164 syslog
    m = SYSLOG_RE.match(line)
    if m:
        dt = datetime(year, MONTHS.get(m.group("mon"), 1), int(m.group("day")),
                      *map(int, m.group("time").split(":")), tzinfo=tz)
        return ("syslog", dt, m.group("host"), m.group("proc"), m.group("msg"))
    # key-value / logfmt (FortiGate, appliances)
    kv = parse_kv(line)
    if kv is not None:
        ts, host, actor = kv
        return ("keyvalue", ts, host, actor, line)
    return ("raw", None, "", "", line)


def coerce_ts(ts, tz: timezone):
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=tz)
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                "%b %d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            dt = datetime.strptime(str(ts), fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=tz)
        except ValueError:
            continue
    return None


def parse_csv_file(path, tz, events):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        tcol = next((c for c in (reader.fieldnames or [])
                     if c and c.lower() in ("timestamp", "time", "date", "@timestamp")), None)
        for row in reader:
            dt = coerce_ts(row.get(tcol) if tcol else None, tz)
            events.append(Event(_iso(dt) if dt else "",
                                path, "csv", row.get("host", ""),
                                row.get("src_ip") or row.get("user") or "",
                                json.dumps(row, ensure_ascii=False)))


def try_cloudtrail(path, tz, events) -> bool:
    """Parse an AWS CloudTrail JSON file ({"Records":[...]}) or a JSON array.
    Returns True if handled; False to fall back to JSON-lines parsing."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            doc = json.load(f)
    except (json.JSONDecodeError, ValueError):
        return False  # likely JSON-lines; let the line parser handle it
    records = doc.get("Records") if isinstance(doc, dict) else doc
    if not isinstance(records, list):
        return False
    for r in records:
        if not isinstance(r, dict):
            continue
        dt = coerce_ts(r.get("eventTime"), tz)
        ident = r.get("userIdentity", {}) or {}
        actor = (r.get("sourceIPAddress") or ident.get("arn")
                 or ident.get("userName") or "")
        msg = f'{r.get("eventName", "")} @ {r.get("eventSource", "")} ' \
              f'[{r.get("awsRegion", "")}]'
        events.append(Event(_iso(dt) if dt else "", path, "cloudtrail",
                            r.get("recipientAccountId", ""), actor, msg.strip()))
    return True


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", help="log files (globs ok)")
    ap.add_argument("--tz", default="+00:00", help="assumed TZ for naive timestamps, e.g. +07:00")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year for syslog lines that omit it")
    ap.add_argument("--out", default="-", help="output file (default stdout)")
    ap.add_argument("--format", choices=("csv", "json"), default="csv")
    args = ap.parse_args()

    sign = 1 if args.tz[0] != "-" else -1
    hh, mm = (int(x) for x in args.tz.lstrip("+-").split(":"))
    tz = timezone(sign * timedelta(hours=hh, minutes=mm))

    files = []
    for pat in args.inputs:
        files.extend(sorted(glob.glob(pat)))
    if not files:
        sys.exit("no input files matched")

    events: list[Event] = []
    coc = []  # chain of custody
    for path in files:
        coc.append((path, sha256(path)))
        if path.lower().endswith(".csv"):
            parse_csv_file(path, tz, events)
            continue
        # AWS CloudTrail / whole-file JSON ({"Records": [...]} or a JSON array)
        if path.lower().endswith(".json") and try_cloudtrail(path, tz, events):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_line(line, tz, args.year)
                if not parsed:
                    continue
                stype, ts, host, actor, msg = parsed
                dt = coerce_ts(ts, tz)
                events.append(Event(_iso(dt) if dt else "", path, stype,
                                    host or "", actor or "", msg))

    events.sort(key=lambda e: (e.timestamp == "", e.timestamp))

    sys.stderr.write("Chain of custody (SHA-256):\n")
    for p, h in coc:
        sys.stderr.write(f"  {h}  {p}\n")
    sys.stderr.write(f"Parsed {len(events)} events from {len(files)} file(s).\n")

    out = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    try:
        if args.format == "json":
            json.dump([asdict(e) for e in events], out, ensure_ascii=False, indent=2)
        else:
            w = csv.DictWriter(out, fieldnames=list(asdict(events[0]).keys())
                               if events else ["timestamp"])
            w.writeheader()
            for e in events:
                w.writerow(asdict(e))
    finally:
        if out is not sys.stdout:
            out.close()


if __name__ == "__main__":
    main()
