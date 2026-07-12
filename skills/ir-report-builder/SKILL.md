---
name: ir-report-builder
description: Analyze security logs and incident data to reconstruct an attack timeline, build an incident response plan following NIST SP 800-61 / SANS PICERL, and produce a detailed technical report plus a concise executive summary (Thai + English). Use when the user mentions 'IR report,' 'incident response report,' 'incident analysis,' 'log analysis for incident,' 'attack timeline,' 'root cause analysis,' 'executive summary of incident,' 'post-incident report,' 'IR plan,' 'containment plan,' 'สรุปเหตุการณ์,' 'รายงานการตอบสนองเหตุการณ์,' 'วิเคราะห์ล็อก,' 'รายงานผู้บริหาร,' or has raw logs / alerts and needs them turned into an investigation and report.
allowed-tools: Read, Grep, Glob, Bash, Write
---

# IR Report Builder

Turn raw logs, alerts, and incident notes into a defensible investigation: a reconstructed timeline, a response plan mapped to a recognized methodology, and two audiences' worth of reporting — deep technical detail for responders and a tight executive summary for leadership.

> **Defensive use.** This skill is for authorized incident response on systems you own or are engaged to defend. Preserve evidence integrity; never alter source logs — work on copies.

## Activation triggers

Use this skill when the user:
- Provides logs (firewall, EDR, auth, web, proxy, DNS, cloud audit) and asks "what happened."
- Asks for an incident report, post-incident review, or executive summary.
- Needs an IR plan, containment/eradication/recovery steps, or a lessons-learned writeup.
- Wants a timeline or root-cause analysis from scattered data.

## Methodology

Follow **NIST SP 800-61r2** phases, cross-referenced with **SANS PICERL**:
Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident.
Map adversary behavior to **MITRE ATT&CK** technique IDs wherever the evidence supports it.

## Workflow

1. **Intake & scope.** Ask for (or infer from provided data): incident type, affected assets, detection time, data sources available, and business criticality. Confirm the reporting window and time zone. Never assume authorization — confirm it.

2. **Normalize the evidence.** Identify each log source and its format. Use `scripts/log_timeline.py` to parse common formats (RFC3164/RFC5424 syslog, JSON lines, CSV, CEF, Apache/Nginx access, FortiGate & appliance key-value/logfmt, and AWS CloudTrail JSON) into a single normalized, timezone-aligned event list. Keep a hash of every source file for chain of custody.

3. **Reconstruct the timeline.** Order events chronologically. Flag the *initial access*, *first malicious action*, *lateral movement*, *privilege escalation*, *impact*, and *last observed activity*. Note gaps in logging as gaps, not as absence of activity.

4. **Analyze.**
   - Extract IOCs (IPs, domains, hashes, user accounts, file paths) into `resources/ioc-extract.md` shape.
   - Map each observed step to a MITRE ATT&CK technique.
   - Determine root cause and the exploited weakness.
   - Assess blast radius: what was accessed, exfiltrated, or altered.

5. **Build the IR plan.** Produce concrete Containment / Eradication / Recovery actions with owners and priority. Distinguish *already done* vs *recommended next*.

6. **Write two deliverables.**
   - **Technical report** → fill `templates/ir-report-template.md`. Dense, evidence-cited, reproducible.
   - **Executive summary** → fill `templates/exec-summary-template.md`. One page, business-impact-first, no jargon, Thai + English. Answer: what happened, what's the impact, is it contained, what do we need from leadership.

7. **Quality gate.** Every claim in the report must cite an evidence line (timestamp + source). Mark anything inferred as *assessed with [high/medium/low] confidence*. List logging/visibility gaps explicitly.

## Output format

- Technical report: Markdown, sectioned per the template, with an appendix of raw evidence excerpts and IOC tables.
- Executive summary: single page, bilingual, leads with impact and status. Use a severity label (Critical/High/Medium/Low) and a one-line "bottom line up front."

## Handoffs

- IOCs and observed techniques → feed into `siem-detection-engineer` to build detections that would have caught this earlier.
- Containment actions that should be automated → feed into `soar-playbook-builder`.
