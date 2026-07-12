#!/usr/bin/env python3
"""
sigma_to_queries.py — first-pass conversion of a Sigma rule to SIEM queries.

Dependency-free (stdlib only). Parses the common Sigma subset produced by this
skill's template (selection maps with `field: value` or `field: [list]`, optional
filter maps, and a `condition: selection and not filter...`) and emits approximate
Splunk SPL, Microsoft Sentinel KQL, and Elastic EQL.

THIS IS A STARTING POINT, NOT A DROP-IN RULE. Always hand-review:
field names must be mapped to the target schema (see resources/log-source-mapping.md),
and count/timeframe logic is only sketched. For production-grade conversion consider
the official `sigma-cli` / pySigma with the right backend + field-mapping pipeline.

Usage:
    python3 sigma_to_queries.py rule.yml
    python3 sigma_to_queries.py --platform kql rule.yml
"""
from __future__ import annotations
import argparse
import re
import sys

MODS = ("contains", "startswith", "endswith", "re", "all")


def parse_sigma(text: str) -> dict:
    """Minimal indentation-aware parser for the Sigma subset this skill emits.

    Handles: top-level title/level, a detection: block containing named groups
    (indent 2) whose fields (indent 4) are scalars or lists (indent >=6 '- '),
    plus condition:/timeframe: keys.
    """
    lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    title = level = None
    detection: dict = {}
    condition = "selection"
    timeframe = None
    in_detection = False
    cur_group = None
    cur_field = None

    for raw in lines:
        indent = len(raw) - len(raw.lstrip())
        s = raw.strip()

        if indent == 0:
            in_detection = (s == "detection:")
            cur_group = cur_field = None
            if s.startswith("title:"):
                title = s.split(":", 1)[1].strip()
            elif s.startswith("level:"):
                level = s.split(":", 1)[1].strip()
            continue

        if not in_detection:
            continue

        if indent == 2:
            if s.startswith("condition:"):
                condition = s.split(":", 1)[1].strip()
                cur_group = cur_field = None
            elif s.startswith("timeframe:"):
                timeframe = s.split(":", 1)[1].strip()
                cur_group = cur_field = None
            elif s.endswith(":"):
                cur_group = s[:-1].strip()
                detection.setdefault(cur_group, {})
                cur_field = None
        elif indent >= 4 and cur_group is not None:
            if s.startswith("- "):
                if cur_field is not None:
                    detection[cur_group][cur_field].append(s[2:].strip())
            elif ":" in s:
                field, _, val = s.partition(":")
                field = field.strip()
                val = val.strip()
                detection[cur_group][field] = [] if val == "" else [val]
                cur_field = field

    return {"title": title, "level": level, "detection": detection,
            "condition": condition, "timeframe": timeframe}


def _clean(v: str) -> str:
    return v.strip().strip("'\"")


def field_clause(field: str, values: list, dialect: str) -> str:
    base, _, mod = field.partition("|")
    vals = [_clean(v) for v in values]
    parts = []
    for v in vals:
        if dialect == "spl":
            if mod in ("contains", "startswith", "endswith"):
                v2 = {"contains": f"*{v}*", "startswith": f"{v}*", "endswith": f"*{v}"}[mod]
                parts.append(f'{base}="{v2}"')
            else:
                parts.append(f'{base}="{v}"')
        elif dialect == "kql":
            op = {"contains": "contains", "startswith": "startswith",
                  "endswith": "endswith", "re": "matches regex"}.get(mod, "==")
            q = v if op == "matches regex" else f'"{v}"'
            parts.append(f'{base} {op} {q}')
        elif dialect == "eql":
            if mod in ("contains", "startswith", "endswith"):
                wild = {"contains": f"*{v}*", "startswith": f"{v}*", "endswith": f"*{v}"}[mod]
                parts.append(f'{base} : "{wild}"')
            else:
                parts.append(f'{base} == "{v}"')
    joiner = " or " if len(parts) > 1 else " and "
    return "(" + joiner.join(parts) + ")" if len(parts) > 1 else parts[0] if parts else "true"


def group_clause(fields: dict, dialect: str) -> str:
    return " and ".join(field_clause(f, v, dialect) for f, v in fields.items() if v)


def build(cond: str, det: dict, dialect: str) -> str:
    groups = {k: v for k, v in det.items() if not k.startswith("__") and isinstance(v, dict)}
    expr = cond or "selection"
    for name, fields in groups.items():
        clause = group_clause(fields, dialect) or "true"
        expr = re.sub(rf"\b{name}\b", f"({clause})", expr)
    expr = expr.replace(" and not ", " AND NOT ").replace(" and ", " AND ").replace(" or ", " OR ")
    if dialect == "kql":
        return expr.replace(" AND NOT ", " and not ").replace(" AND ", " and ").replace(" OR ", " or ")
    if dialect == "eql":
        return expr.replace(" AND NOT ", " and not ").replace(" AND ", " and ").replace(" OR ", " or ")
    return expr  # spl handled below


def to_spl(rule):
    where = build(rule["condition"], rule["detection"], "spl")
    where = where.replace(" AND NOT ", " NOT ").replace(" AND ", " ").replace(" OR ", " OR ")
    return f"index=* {where}\n| stats count min(_time) max(_time) by src_ip user host"


def to_kql(rule):
    where = build(rule["condition"], rule["detection"], "kql")
    return f"SecurityEvent\n| where {where}\n| summarize count(), min(TimeGenerated), max(TimeGenerated) by SourceIP, AccountName"


def to_eql(rule):
    where = build(rule["condition"], rule["detection"], "eql")
    return f"any where {where}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("rule", help="Sigma YAML file")
    ap.add_argument("--platform", choices=("all", "spl", "kql", "eql"), default="all")
    args = ap.parse_args()

    with open(args.rule, encoding="utf-8") as f:
        rule = parse_sigma(f.read())

    print(f"# {rule.get('title') or 'rule'}  (level: {rule.get('level')})")
    print(f"# condition: {rule['condition']}")
    print("# NOTE: first-pass output — map fields to your schema and review before deploying.\n")

    if args.platform in ("all", "spl"):
        print("## Splunk SPL\n```spl")
        print(to_spl(rule)); print("```\n")
    if args.platform in ("all", "kql"):
        print("## Microsoft Sentinel KQL\n```kql")
        print(to_kql(rule)); print("```\n")
    if args.platform in ("all", "eql"):
        print("## Elastic EQL\n```eql")
        print(to_eql(rule)); print("```")


if __name__ == "__main__":
    main()
