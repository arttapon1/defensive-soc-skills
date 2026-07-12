# Defensive SOC Skills for Claude Code

A suite of three **original** Claude Code / Agent Skills for blue-team / SOC work.
They form a pipeline: **investigate → detect → respond**.

> 📖 **Full usage guide → [MANUAL.md](MANUAL.md)** (install, how each skill activates, helper-script CLI usage, FAQ)

| Skill | What it does | Handoff |
|---|---|---|
| **ir-report-builder** | Analyze all logs → attack timeline, IR plan (NIST 800-61 / PICERL), detailed technical report + executive summary | IOC + technique → detection |
| **siem-detection-engineer** | From data / attack behavior → author Sigma rules, then convert to SPL / KQL / EQL / QRadar / Wazuh + MITRE ATT&CK mapping + false-positive estimate | detection → response |
| **soar-playbook-builder** | Build SOAR playbooks that call device APIs (Firewall/WAF/IPS/DLP) for automated blocking + threat-intel enrichment (VirusTotal/AbuseIPDB/OTX/Group-IB), with guardrails & rollback | actions → incident record |

---

## ⚠️ Authorization & safety

For **authorized defensive use only** — systems you own or are engaged to protect.
- Preserve evidence integrity; work on copies of logs.
- The SOAR response scripts are **dry-run by default** and enforce a never-block
  allowlist. Automation that blocks production traffic can cause outages — review
  before flipping `--commit`.

---

## What's original here

Every skill, script, and template in this repo is written from scratch for this
suite. No third-party skill content is bundled. External *tools and services*
(VirusTotal, MITRE ATT&CK, Sigma, vendor APIs) are only referenced/integrated, not
redistributed, and remain under their own terms.

## Included, working helper scripts (stdlib-only, no pip install)

| Script | Purpose | Verified |
|---|---|---|
| `ir-report-builder/scripts/log_timeline.py` | Normalize syslog (RFC3164/5424) / JSON / CSV / CEF / access / FortiGate KV / AWS CloudTrail into one sorted timeline + SHA-256 chain of custody | ✅ |
| `siem-detection-engineer/scripts/sigma_to_queries.py` | First-pass Sigma → SPL/KQL/EQL conversion | ✅ |
| `soar-playbook-builder/scripts/enrich_ioc.py` | Multi-source IOC reputation (VT/AbuseIPDB/OTX/Group-IB) | ✅ |
| `soar-playbook-builder/scripts/respond_block.py` | Block/unblock via Cloudflare / Palo Alto / FortiGate / CrowdStrike, dry-run + allowlist guard | ✅ |

---

## Install

```bash
git clone https://github.com/arttapon1/defensive-soc-skills.git
cd defensive-soc-skills
./install.sh          # copies the 3 skills into ~/.claude/skills/
```

Or manually:
```bash
cp -R skills/* ~/.claude/skills/
```

Start a new Claude Code session, then just describe the task — e.g. *"analyze these
logs and write an IR report"*, *"write a detection rule for this incident"*, *"build
a playbook to block this IP on the firewall"* — and the matching skill activates.

## License
MIT — see [LICENSE](LICENSE). You wrote it; you own it.
