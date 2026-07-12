# Defensive SOC Skills for Claude Code

A suite of three **original** Claude Code / Agent Skills for blue-team / SOC work.
They form a pipeline: **investigate → detect → respond**.

ชุด Agent Skills สาย **defensive / SOC** ที่เขียนขึ้นเอง 3 ตัว ต่อกันเป็น pipeline: สืบสวนเหตุการณ์ → ออกแบบ detection → ตอบโต้อัตโนมัติ

> 📖 **คู่มือการใช้งานฉบับละเอียด → [MANUAL.md](MANUAL.md)** (ติดตั้ง, วิธีเรียกแต่ละ skill, การใช้ script, FAQ)

| Skill | ทำอะไร | Handoff |
|---|---|---|
| **ir-report-builder** | วิเคราะห์ log ทั้งหมด → สร้าง attack timeline, IR plan (NIST 800-61 / PICERL), รายงานเทคนิคละเอียด + สรุปผู้บริหาร (ไทย/อังกฤษ) | IOC + technique → detection |
| **siem-detection-engineer** | จากข้อมูล/พฤติกรรมโจมตี → เขียน Sigma rule แล้วแปลงเป็น SPL / KQL / EQL / QRadar / Wazuh + map MITRE ATT&CK + ประเมิน false positive | detection → response |
| **soar-playbook-builder** | สร้าง SOAR playbook เชื่อม API ไป Firewall/WAF/IPS/DLP เพื่อบล็อกอัตโนมัติ + enrich จาก VirusTotal/AbuseIPDB/OTX/Group-IB พร้อม guardrail & rollback | actions → incident record |

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
| `ir-report-builder/scripts/log_timeline.py` | Normalize syslog/JSON/CSV/CEF/access logs into one sorted timeline + SHA-256 chain of custody | ✅ |
| `siem-detection-engineer/scripts/sigma_to_queries.py` | First-pass Sigma → SPL/KQL/EQL conversion | ✅ |
| `soar-playbook-builder/scripts/enrich_ioc.py` | Multi-source IOC reputation (VT/AbuseIPDB/OTX/Group-IB) | ✅ |
| `soar-playbook-builder/scripts/respond_block.py` | Firewall/WAF block/unblock, dry-run + allowlist guard | ✅ |

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

Start a new Claude Code session, then just describe the task — e.g. *"วิเคราะห์ log
พวกนี้แล้วทำรายงาน IR"*, *"เขียน detection rule จากเหตุการณ์นี้"*, *"สร้าง playbook
บล็อก IP นี้บน firewall"* — and the matching skill activates.

## License
MIT — see [LICENSE](LICENSE). You wrote it; you own it.
