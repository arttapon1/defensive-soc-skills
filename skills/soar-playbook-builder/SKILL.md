---
name: soar-playbook-builder
description: Design and generate SOAR automation playbooks that enrich alerts with threat intelligence (VirusTotal, Group-IB, AbuseIPDB, OTX) and orchestrate automated response via device APIs — blocking IOCs on firewalls (Palo Alto, Fortinet, Check Point), WAFs (Cloudflare, AWS WAF, F5), IPS, DLP, and EDR. Produces vendor-neutral playbook definitions with decision logic, approval gates, rollback, and safety guardrails. Use when the user mentions 'SOAR,' 'playbook,' 'automation playbook,' 'automated response,' 'auto-block,' 'block IP on firewall,' 'API integration,' 'enrich IOC,' 'VirusTotal API,' 'Group-IB,' 'threat intel enrichment,' 'firewall API,' 'WAF API,' 'orchestration,' 'auto containment,' 'สร้าง playbook,' 'ระงับการโจมตีอัตโนมัติ,' 'เชื่อม API firewall,' or wants to automate detection-to-response.
allowed-tools: Read, Grep, Glob, Bash, Write
---

# SOAR Playbook Builder

Turn a detection into an automated, auditable response: enrich the indicator, decide with explicit logic, act through device APIs, and always leave a rollback path. Playbooks are authored vendor-neutral, then bound to concrete integrations.

> **Safety first — automation that blocks production traffic can cause outages.**
> Every generated playbook defaults to **dry-run**, requires an **approval gate** for
> any destructive/blocking action on production, scopes blocks with a **TTL/expiry**,
> and ships with a **rollback** step. Only operate against infrastructure you are
> authorized to control.

## Activation triggers

- The user wants to auto-enrich alerts with threat intel.
- The user wants to auto-block/contain IOCs on firewall / WAF / IPS / DLP / EDR.
- The user wants to orchestrate a multi-step response with decision logic.

## Design principles

1. **Enrich before you act.** Never block on a raw indicator. Gather reputation from multiple sources and require a confidence threshold.
2. **Human-in-the-loop for blast radius.** Auto-act on low-risk, reversible steps; gate anything that can break production behind an approval.
3. **Everything is reversible & time-boxed.** Blocks carry a TTL and an explicit rollback action. Log every action with who/what/when/why.
4. **Idempotent & rate-aware.** Re-running must not double-apply. Respect API rate limits and back off.
5. **Fail safe, not open.** On integration error, alert a human — do not silently drop the response.

## Workflow

1. **Define the trigger.** What detection/alert starts this playbook? (Handoff from `siem-detection-engineer`.) Capture the indicator(s) and context.

2. **Enrichment stage.** Choose intel sources from `resources/integration-catalog.md`. Use `scripts/enrich_ioc.py` as the reference client (VirusTotal, AbuseIPDB, OTX, Group-IB placeholders). Compute an aggregate risk score and confidence.

3. **Decision logic.** Write explicit conditions: e.g. `if malicious_votes >= N and confidence == high -> block; elif suspicious -> tag + escalate; else -> close as FP`. No implicit "always block."

4. **Response actions.** Map each action to a device integration in `resources/integration-catalog.md`. Use `scripts/respond_block.py` as the reference client for firewall/WAF blocking with dry-run, TTL, and rollback. Sequence: contain → notify → ticket.

5. **Guardrails.** Add: allowlist of never-block assets (corp ranges, partners, monitoring), max-actions-per-run circuit breaker, approval gate for production, and full audit logging.

6. **Emit the playbook.** Fill `templates/playbook-template.yml` — a vendor-neutral spec with trigger, enrichment, decision, actions, guardrails, rollback. Optionally note how it maps to a specific platform (Cortex XSOAR, Splunk SOAR, Tines, Shuffle, native SIEM automation).

7. **Test plan.** Provide a dry-run walkthrough with a sample alert, expected decision, and the exact API calls that *would* fire (without firing them).

## Output format

- Playbook YAML (vendor-neutral) per the template.
- A decision table (condition → action).
- Integration binding notes (which API, which credential, which endpoint).
- A dry-run test walkthrough.
- Guardrail & rollback summary.

## Handoffs

- Triggered by detections from `siem-detection-engineer`.
- Blocked/contained IOCs and actions taken → feed back into `ir-report-builder` for the incident record.
