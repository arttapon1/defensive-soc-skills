# User Manual — Defensive SOC Skills

A detailed guide to the three defensive / SOC Agent Skills in this suite.

> The suite is designed to work as a pipeline: **investigate → detect → respond**
> (`ir-report-builder` → `siem-detection-engineer` → `soar-playbook-builder`)

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [How skills work](#3-how-skills-work)
4. [Skill 1 — ir-report-builder](#4-skill-1--ir-report-builder)
5. [Skill 2 — siem-detection-engineer](#5-skill-2--siem-detection-engineer)
6. [Skill 3 — soar-playbook-builder](#6-skill-3--soar-playbook-builder)
7. [End-to-end pipeline workflow](#7-end-to-end-pipeline-workflow)
8. [Security & safety notes](#8-security--safety-notes)
9. [FAQ / troubleshooting](#9-faq--troubleshooting)

---

## 1. Prerequisites

| Requirement | Details |
|---|---|
| Claude Code | Installed and working (CLI / IDE / desktop) |
| Python 3.8+ | To run the helper scripts (**stdlib only — no `pip install`**) |
| Authorization | Use only on systems you own or are engaged to defend |
| API keys (SOAR only) | VirusTotal / AbuseIPDB / OTX / Group-IB — needed only for live enrichment (runs partially without them) |

Check Python:
```bash
python3 --version
```

---

## 2. Installation

```bash
git clone https://github.com/arttapon1/defensive-soc-skills.git
cd defensive-soc-skills
./install.sh          # copies all 3 skills into ~/.claude/skills/
```

Install a single skill manually:
```bash
cp -R skills/ir-report-builder ~/.claude/skills/
```

**Important:** after installing, **start a new Claude Code session** so the skills load.

Verify the install:
```bash
ls ~/.claude/skills/ | grep -E 'ir-report|siem-detection|soar-playbook'
```

---

## 3. How skills work

- Skills need **no special command** — just describe the task in natural language and
  Claude picks the matching skill based on the words you use (trigger words).
- Each skill has this structure:
  ```
  skills/<skill-name>/
  ├── SKILL.md      ← the skill's brain (Claude reads this)
  ├── scripts/      ← code Claude runs automatically
  ├── templates/    ← report / rule / playbook templates
  └── resources/    ← reference data (field mapping, integration catalog)
  ```
- You give the instruction in plain language — Claude decides which script to run and when.

---

## 4. Skill 1 — ir-report-builder

**Purpose:** turn raw logs/alerts into an attack timeline, an IR plan (NIST SP 800-61 /
SANS PICERL), a detailed technical report, and an executive summary.

### How to trigger it
Use a sentence containing words like: *"analyze logs"*, *"IR report"*,
*"incident summary"*, *"executive summary"*, *"attack timeline"*, *"root cause"*.

**Example prompt:**
> "Here are the firewall and auth-server logs from when we were attacked. Analyze them
> and produce an IR report with an executive summary."

### What the skill does
1. Runs `log_timeline.py` to merge multiple log formats into one timeline + records a
   hash of each file for chain of custody.
2. Reconstructs the attack (initial access → lateral movement → impact), mapped to MITRE ATT&CK.
3. Extracts IOCs and assesses impact.
4. Fills two templates: a technical report + a one-page executive summary.

### Using the helper script directly
```bash
cd ~/.claude/skills/ir-report-builder

# Merge logs into a timeline (CSV)
python3 scripts/log_timeline.py --tz +07:00 --out timeline.csv fw.log auth.json access.log

# Emit JSON instead
python3 scripts/log_timeline.py --tz +07:00 --format json --out timeline.json *.log
```
Supported: RFC3164/RFC5424 syslog, JSON lines, CSV, CEF, Apache/Nginx access log,
**FortiGate & appliance key-value/logfmt** (`date=... time=... srcip=...`), and **AWS CloudTrail** JSON.
The stderr output prints a SHA-256 of every input file as evidence.

### Key files
- `templates/ir-report-template.md` — technical report skeleton (evidence, timeline, ATT&CK, IOC, PICERL)
- `templates/exec-summary-template.md` — one-page executive summary (business-impact-first)

---

## 5. Skill 2 — siem-detection-engineer

**Purpose:** turn data / attack behavior into detection rules — authored as **Sigma**
(vendor-neutral) and converted to Splunk SPL / Sentinel KQL / Elastic EQL / QRadar /
Wazuh, with MITRE ATT&CK mapping and false-positive estimates.

### How to trigger it
Trigger words: *"detection rule"*, *"SIEM rule"*, *"Sigma rule"*, *"SPL"*, *"KQL"*,
*"detection engineering"*, *"detect this attack"*.

**Example prompt:**
> "From this brute-force-then-successful-login incident, write a detection rule for
> Splunk and Sentinel."

### What the skill does
1. States a detection hypothesis tied to an ATT&CK technique.
2. Authors a Sigma rule from the template.
3. Converts it to multiple platforms.
4. Aligns field names with the real schema (the #1 reason rules don't fire).
5. Sets severity, FP rate, and positive/negative test cases.

### Using the helper script directly
```bash
cd ~/.claude/skills/siem-detection-engineer

# Convert a Sigma rule to all platforms
python3 scripts/sigma_to_queries.py rule.yml

# Pick a single platform
python3 scripts/sigma_to_queries.py --platform kql rule.yml
```
> ⚠️ Output is **first-pass** — always review and map fields to your real schema before deploying.

### Key files
- `templates/sigma-rule-template.yml` — Sigma rule skeleton with falsepositives / tuning / test slots
- `resources/log-source-mapping.md` — cross-SIEM field mapping table (Splunk CIM ↔ ECS ↔ KQL ↔ ...)
  plus a pre-deployment checklist

---

## 6. Skill 3 — soar-playbook-builder

**Purpose:** build SOAR playbooks — enrich IOCs with threat intel, then auto-block via
Firewall/WAF/IPS/DLP/EDR APIs, with guardrails, approval gates, and rollback.

### How to trigger it
Trigger words: *"SOAR"*, *"playbook"*, *"automated response"*, *"auto-block"*,
*"firewall API"*, *"enrich IOC"*.

**Example prompt:**
> "Build a playbook: when the SIEM flags a suspicious IP, check VirusTotal first; if
> malicious, auto-block it on Cloudflare — but production requires approval."

### What the skill does
1. Defines the trigger + indicator.
2. Enriches from multiple sources (VT / AbuseIPDB / OTX / Group-IB) → aggregate verdict + confidence.
3. Writes explicit decision logic (malicious+high → block, suspicious → escalate, else → close).
4. Binds actions to device APIs (dry-run first).
5. Adds guardrails: never-block allowlist, approval gate, TTL, rollback, audit log.

### Configure API keys (store in env — never hardcode)
```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export OTX_API_KEY="..."
# firewall/WAF/EDR
export CF_API_TOKEN="..."; export CF_ZONE="..."           # Cloudflare
export PANOS_API_KEY="..."; export PANOS_HOST="..."        # Palo Alto
export FORTI_API_TOKEN="..."; export FORTI_HOST="..."      # FortiGate
export FALCON_TOKEN="..."; export FALCON_CLOUD="api.crowdstrike.com"  # CrowdStrike
```

### Using the helper scripts directly
```bash
cd ~/.claude/skills/soar-playbook-builder

# 1) Enrich an IOC (read-only, safe)
python3 scripts/enrich_ioc.py 203.0.113.10
python3 scripts/enrich_ioc.py --type hash 44d88612fea8a8f36de82e1278abb02f

# 2) Block — DRY-RUN by default (nothing is sent)
python3 scripts/respond_block.py --integration cloudflare --action block \
    --indicator 203.0.113.10 --ttl 24h

# 3) Block for real — you must pass --commit and set the API key first
python3 scripts/respond_block.py --integration cloudflare --action block \
    --indicator 203.0.113.10 --ttl 24h --commit

# 4) Unblock (rollback)
python3 scripts/respond_block.py --integration cloudflare --action unblock \
    --indicator 203.0.113.10 --commit

# FortiGate — create an address object to bind to a deny policy / blocklist group
python3 scripts/respond_block.py --integration fortinet --action block \
    --indicator 203.0.113.10 --commit

# CrowdStrike Falcon — add a custom IOC (action=prevent); supports ip/domain/hash
python3 scripts/respond_block.py --integration crowdstrike --action block \
    --indicator 44d88612fea8a8f36de82e1278abb02f --commit
```

**Currently supported integrations:** `cloudflare`, `paloalto`, `fortinet`, `crowdstrike`
(add more by writing a function in `respond_block.py` and registering it in `INTEGRATIONS`).

> 🛡️ **Built-in safety:**
> - Dry-run is the default — only `--commit` actually sends the API call.
> - The allowlist refuses to block internal IPs (RFC1918) and any ranges you add.
> - Destructive actions are refused if the API key is not set in the environment.

### Key files
- `templates/playbook-template.yml` — vendor-neutral playbook skeleton (trigger/enrich/decision/action/guardrail/rollback)
- `resources/integration-catalog.md` — API catalog (endpoint, env var, rate limit) for VT,
  Palo Alto, Fortinet, Check Point, Cloudflare, AWS WAF, F5, CrowdStrike, and more

---

## 7. End-to-end pipeline workflow

```
  [ Raw logs / alerts ]
         │
         ▼
  ┌────────────────────┐   IOC + ATT&CK technique
  │ ir-report-builder  │ ───────────────────────────┐
  │ investigate + report│                            │
  └────────────────────┘                            ▼
                                        ┌──────────────────────────┐
                                        │ siem-detection-engineer  │
                                        │ write rules to close gaps │
                                        └──────────────────────────┘
                                                     │ detections worth auto-responding to
                                                     ▼
                                        ┌──────────────────────────┐
   actions taken ─────────────────────▶│ soar-playbook-builder    │
   (fed back into incident record)      │ enrich + auto-block       │
                                        └──────────────────────────┘
```

**A realistic chained example:**
1. "Analyze the logs from this incident and write an IR report" → timeline + IOCs + techniques.
2. "Take the techniques from that incident and write a detection rule for Splunk" → Sigma + SPL.
3. "Build a playbook to auto-block these IOCs on the firewall with VirusTotal enrichment" → playbook + dry-run.

---

## 8. Security & safety notes

- ✅ **Authorized systems only** — recon/blocking systems you don't have rights to is illegal.
- ✅ **Preserve evidence integrity** — always analyze copies of logs; never modify originals.
- ✅ **Automation that blocks production can cause outages** — always test dry-run first,
  keep the allowlist complete, and use approval gates for production.
- ✅ **Store API keys in a secrets manager / env** — `.gitignore` already blocks `.env`,
  `*.key`, `*.pem`, and `*.log`; never commit credentials.
- ✅ **Every action needs rollback + audit log** — the playbook template enforces this.

---

## 9. FAQ / troubleshooting

**Q: I typed a task but the skill didn't activate.**
A: (1) Start a new session after installing. (2) Use clearer trigger words such as
"detection rule", "IR report", "playbook". (3) Confirm the folder is in
`~/.claude/skills/` and contains a `SKILL.md`.

**Q: A script raises `ModuleNotFoundError`.**
A: It shouldn't — every script is stdlib-only. Make sure you run `python3` (not an old `python`).

**Q: `enrich_ioc.py` says "no API keys set".**
A: Expected — you haven't set the env vars yet. Set `VT_API_KEY` etc. and re-run.

**Q: `respond_block.py` says "REFUSED: ... never-block allowlist".**
A: Correct behavior — that IP is in a protected range (RFC1918 or a range you added to `NEVER_BLOCK`).

**Q: `sigma_to_queries.py` output fields don't match my SIEM.**
A: It's a first-pass; map fields yourself using `resources/log-source-mapping.md`. For
production, consider `sigma-cli` / pySigma with a backend + field-mapping pipeline.

---

*License: MIT — see [LICENSE](LICENSE) · Issues / PRs welcome.*
