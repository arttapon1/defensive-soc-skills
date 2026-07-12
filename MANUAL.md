# คู่มือการใช้งาน — Defensive SOC Skills

คู่มือฉบับละเอียดสำหรับชุด Agent Skills สาย defensive/SOC ทั้ง 3 ตัว
(User Manual — Thai primary, English notes inline)

> ทั้งชุดออกแบบมาให้ทำงานต่อกันเป็น pipeline: **สืบสวน → ตรวจจับ → ตอบโต้**
> (`ir-report-builder` → `siem-detection-engineer` → `soar-playbook-builder`)

---

## สารบัญ

1. [ข้อกำหนดเบื้องต้น](#1-ข้อกำหนดเบื้องต้น)
2. [การติดตั้ง](#2-การติดตั้ง)
3. [แนวคิดพื้นฐาน: skill ทำงานอย่างไร](#3-แนวคิดพื้นฐาน-skill-ทำงานอย่างไร)
4. [Skill 1 — ir-report-builder](#4-skill-1--ir-report-builder)
5. [Skill 2 — siem-detection-engineer](#5-skill-2--siem-detection-engineer)
6. [Skill 3 — soar-playbook-builder](#6-skill-3--soar-playbook-builder)
7. [Workflow ต่อกันทั้ง pipeline](#7-workflow-ต่อกันทั้ง-pipeline)
8. [ความปลอดภัย & ข้อควรระวัง](#8-ความปลอดภัย--ข้อควรระวัง)
9. [FAQ / แก้ปัญหาที่พบบ่อย](#9-faq--แก้ปัญหาที่พบบ่อย)

---

## 1. ข้อกำหนดเบื้องต้น

| สิ่งที่ต้องมี | รายละเอียด |
|---|---|
| Claude Code | ติดตั้งแล้ว และใช้งานได้ (CLI / IDE / desktop) |
| Python 3.8+ | สำหรับรัน helper scripts (ใช้ **stdlib ล้วน ไม่ต้อง pip install**) |
| สิทธิ์การใช้งาน | ใช้กับระบบที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้ป้องกันเท่านั้น |
| API keys (เฉพาะ SOAR) | VirusTotal / AbuseIPDB / OTX / Group-IB — ถ้าจะ enrich จริง (ไม่มีก็รันได้แบบ partial) |

ตรวจ Python:
```bash
python3 --version
```

---

## 2. การติดตั้ง

```bash
git clone https://github.com/arttapon1/defensive-soc-skills.git
cd defensive-soc-skills
./install.sh          # คัดลอก skill ทั้ง 3 ไปที่ ~/.claude/skills/
```

ติดตั้งเองแบบเลือกตัว:
```bash
cp -R skills/ir-report-builder ~/.claude/skills/
```

**สำคัญ:** หลังติดตั้ง ให้ **เปิด Claude Code session ใหม่** เพื่อให้ระบบโหลด skill

ตรวจว่าติดตั้งแล้ว:
```bash
ls ~/.claude/skills/ | grep -E 'ir-report|siem-detection|soar-playbook'
```

---

## 3. แนวคิดพื้นฐาน: skill ทำงานอย่างไร

- Skill **ไม่ต้องเรียกด้วยคำสั่งพิเศษ** — แค่พิมพ์งานเป็นภาษาธรรมชาติ (ไทยหรืออังกฤษ)
  แล้ว Claude จะเลือก skill ที่ตรงกับงานให้เอง โดยดูจากคำที่คุณพิมพ์ (trigger words)
- แต่ละ skill มีโครงสร้าง:
  ```
  skills/<ชื่อ skill>/
  ├── SKILL.md      ← สมองของ skill (Claude อ่านอันนี้)
  ├── scripts/      ← โค้ดที่ Claude เรียกใช้อัตโนมัติ
  ├── templates/    ← เทมเพลตรายงาน/rule/playbook
  └── resources/    ← ข้อมูลอ้างอิง (field mapping, integration catalog)
  ```
- คุณสั่งงานเป็นภาษาคน — Claude เป็นคนตัดสินใจว่าจะรัน script ตัวไหน เมื่อไหร่

---

## 4. Skill 1 — ir-report-builder

**หน้าที่:** เอา log/alert ดิบ มาสร้าง attack timeline, IR plan (NIST SP 800-61 / SANS
PICERL), รายงานเทคนิคละเอียด + สรุปผู้บริหาร (ไทย/อังกฤษ)

### วิธีเรียกใช้
พิมพ์ประโยคที่มีคำพวกนี้: *"วิเคราะห์ล็อก"*, *"ทำรายงาน IR"*, *"สรุปเหตุการณ์"*,
*"รายงานผู้บริหาร"*, *"attack timeline"*, *"root cause"*

**ตัวอย่างคำสั่ง:**
> "นี่ log จาก firewall กับ auth server ตอนโดนโจมตี ช่วยวิเคราะห์แล้วทำรายงาน IR
> พร้อมสรุปผู้บริหารให้หน่อย"

### สิ่งที่ skill ทำให้
1. รัน `log_timeline.py` รวม log หลายฟอร์แมตเป็น timeline เดียว + เก็บ hash เพื่อ chain of custody
2. เรียงลำดับการโจมตี (initial access → lateral movement → impact) map กับ MITRE ATT&CK
3. ดึง IOC และประเมินผลกระทบ
4. เติมเทมเพลต 2 ชุด: รายงานเทคนิค + สรุปผู้บริหาร 1 หน้า

### ใช้ helper script เอง (ถ้าต้องการ)
```bash
cd ~/.claude/skills/ir-report-builder

# รวม log เป็น timeline (CSV)
python3 scripts/log_timeline.py --tz +07:00 --out timeline.csv fw.log auth.json access.log

# ออกเป็น JSON
python3 scripts/log_timeline.py --tz +07:00 --format json --out timeline.json *.log
```
รองรับ: RFC3164/RFC5424 syslog, JSON lines, CSV, CEF, Apache/Nginx access log,
**FortiGate & appliance key-value/logfmt** (`date=... time=... srcip=...`), และ **AWS CloudTrail** JSON
ผลลัพธ์ stderr จะพิมพ์ SHA-256 ของทุกไฟล์ input ไว้เป็นหลักฐาน

### ไฟล์สำคัญ
- `templates/ir-report-template.md` — โครงรายงานเทคนิค (evidence, timeline, ATT&CK, IOC, PICERL)
- `templates/exec-summary-template.md` — สรุปผู้บริหาร 1 หน้า (ไทย/อังกฤษ, เน้น business impact)

---

## 5. Skill 2 — siem-detection-engineer

**หน้าที่:** เอาข้อมูล/พฤติกรรมโจมตี มาออกแบบ detection rule เขียนเป็น **Sigma** (กลาง)
แล้วแปลงเป็น Splunk SPL / Sentinel KQL / Elastic EQL / QRadar / Wazuh + map ATT&CK +
ประเมิน false positive

### วิธีเรียกใช้
คำ trigger: *"สร้าง rule detection"*, *"เขียน rule SIEM"*, *"ตรวจจับการโจมตี"*,
*"Sigma rule"*, *"SPL"*, *"KQL"*, *"detection engineering"*

**ตัวอย่างคำสั่ง:**
> "จากเหตุการณ์ brute force แล้ว login สำเร็จอันนี้ ช่วยเขียน detection rule
> สำหรับ Splunk กับ Sentinel ให้หน่อย"

### สิ่งที่ skill ทำให้
1. ตั้งสมมติฐานการตรวจจับ (detection hypothesis) ผูกกับ ATT&CK technique
2. เขียน Sigma rule จากเทมเพลต
3. แปลงเป็น query หลาย platform
4. เทียบชื่อ field ให้ตรง schema จริง (สาเหตุ #1 ที่ rule ไม่ทำงาน)
5. กำหนด severity, FP rate, และ test case (positive/negative)

### ใช้ helper script เอง
```bash
cd ~/.claude/skills/siem-detection-engineer

# แปลง Sigma rule เป็นทุก platform
python3 scripts/sigma_to_queries.py rule.yml

# เลือก platform เดียว
python3 scripts/sigma_to_queries.py --platform kql rule.yml
```
> ⚠️ ผลลัพธ์เป็น **first-pass** ต้องรีวิว/แก้ field ให้ตรง schema จริงก่อน deploy เสมอ

### ไฟล์สำคัญ
- `templates/sigma-rule-template.yml` — โครง Sigma rule พร้อมช่อง falsepositives / tuning / test
- `resources/log-source-mapping.md` — ตารางเทียบ field ข้าม SIEM (Splunk CIM ↔ ECS ↔ KQL ↔ ...)
  + checklist ก่อน deploy rule

---

## 6. Skill 3 — soar-playbook-builder

**หน้าที่:** สร้าง SOAR playbook — enrich IOC จาก threat intel แล้วสั่งบล็อกอัตโนมัติ
ผ่าน API ของ Firewall/WAF/IPS/DLP/EDR พร้อม guardrail, approval gate, rollback

### วิธีเรียกใช้
คำ trigger: *"สร้าง playbook"*, *"ระงับการโจมตีอัตโนมัติ"*, *"เชื่อม API firewall"*,
*"auto-block"*, *"enrich IOC"*, *"SOAR"*

**ตัวอย่างคำสั่ง:**
> "ทำ playbook: พอ SIEM เจอ IP ต้องสงสัย ให้เช็ค VirusTotal ก่อน ถ้า malicious
> ให้บล็อกที่ Cloudflare อัตโนมัติ แต่ production ต้องมี approval"

### สิ่งที่ skill ทำให้
1. นิยาม trigger + indicator
2. Enrich จากหลายแหล่ง (VT / AbuseIPDB / OTX / Group-IB) → รวมเป็น verdict + confidence
3. เขียน decision logic ชัดเจน (malicious+high → block, suspicious → escalate, else → close)
4. ผูก action กับ API อุปกรณ์ (dry-run ก่อน)
5. ใส่ guardrail: allowlist ห้ามบล็อก, approval gate, TTL, rollback, audit log

### ตั้งค่า API keys (เก็บใน env — ห้าม hardcode)
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

### ใช้ helper script เอง
```bash
cd ~/.claude/skills/soar-playbook-builder

# 1) Enrich IOC (read-only ปลอดภัย)
python3 scripts/enrich_ioc.py 203.0.113.10
python3 scripts/enrich_ioc.py --type hash 44d88612fea8a8f36de82e1278abb02f

# 2) บล็อก — DRY-RUN เป็นค่าเริ่มต้น (ไม่ยิงจริง)
python3 scripts/respond_block.py --integration cloudflare --action block \
    --indicator 203.0.113.10 --ttl 24h

# 3) บล็อกจริง — ต้องใส่ --commit เอง และต้องตั้ง API key แล้ว
python3 scripts/respond_block.py --integration cloudflare --action block \
    --indicator 203.0.113.10 --ttl 24h --commit

# 4) ยกเลิกบล็อก (rollback)
python3 scripts/respond_block.py --integration cloudflare --action unblock \
    --indicator 203.0.113.10 --commit

# FortiGate — สร้าง address object เพื่อผูกกับ deny policy/blocklist group
python3 scripts/respond_block.py --integration fortinet --action block \
    --indicator 203.0.113.10 --commit

# CrowdStrike Falcon — เพิ่ม custom IOC (action=prevent) รองรับ ip/domain/hash
python3 scripts/respond_block.py --integration crowdstrike --action block \
    --indicator 44d88612fea8a8f36de82e1278abb02f --commit
```

**Integration ที่รองรับตอนนี้:** `cloudflare`, `paloalto`, `fortinet`, `crowdstrike`
(เพิ่มตัวอื่นได้โดยเขียนฟังก์ชันใน `respond_block.py` แล้วลงทะเบียนใน `INTEGRATIONS`)

> 🛡️ **กลไกความปลอดภัยในตัว:**
> - Dry-run เป็นค่าเริ่มต้น — ต้อง `--commit` เท่านั้นถึงจะยิง API จริง
> - Allowlist ปฏิเสธการบล็อก IP ภายใน (RFC1918) และช่วงที่คุณกำหนด
> - ถ้าไม่ได้ตั้ง API key จะไม่ยอมทำ destructive action

### ไฟล์สำคัญ
- `templates/playbook-template.yml` — โครง playbook กลาง (trigger/enrich/decision/action/guardrail/rollback)
- `resources/integration-catalog.md` — แคตตาล็อก API (endpoint, env var, rate limit) ของ VT,
  Palo Alto, Fortinet, Check Point, Cloudflare, AWS WAF, F5, EDR ฯลฯ

---

## 7. Workflow ต่อกันทั้ง pipeline

```
  [ Log/Alert ดิบ ]
         │
         ▼
  ┌────────────────────┐   IOC + ATT&CK technique
  │ ir-report-builder  │ ───────────────────────────┐
  │ สืบสวน + รายงาน     │                            │
  └────────────────────┘                            ▼
                                        ┌──────────────────────────┐
                                        │ siem-detection-engineer  │
                                        │ เขียน rule ปิดช่องโหว่     │
                                        └──────────────────────────┘
                                                     │ detection ที่ควร auto-respond
                                                     ▼
                                        ┌──────────────────────────┐
   action ที่ทำ ──────────────────────▶│ soar-playbook-builder    │
   (feed กลับเข้า incident record)      │ enrich + auto-block       │
                                        └──────────────────────────┘
```

**ตัวอย่างการใช้จริงต่อกัน:**
1. "วิเคราะห์ log เหตุการณ์นี้ทำรายงาน IR" → ได้ timeline + IOC + technique
2. "เอา technique จากเหตุการณ์เมื่อกี้ มาเขียน detection rule สำหรับ Splunk" → ได้ Sigma + SPL
3. "ทำ playbook auto-block IOC พวกนี้บน firewall พร้อม enrich VirusTotal" → ได้ playbook + dry-run

---

## 8. ความปลอดภัย & ข้อควรระวัง

- ✅ **ใช้กับระบบที่ได้รับอนุญาตเท่านั้น** — การ recon/block ระบบที่ไม่มีสิทธิ์ผิดกฎหมาย
- ✅ **รักษาความสมบูรณ์ของหลักฐาน** — วิเคราะห์บนสำเนา log เสมอ อย่าแก้ไฟล์ต้นฉบับ
- ✅ **automation ที่บล็อก production ทำให้ระบบล่มได้** — ทดสอบ dry-run ก่อนทุกครั้ง,
  ตั้ง allowlist ให้ครบ, ใช้ approval gate สำหรับ production
- ✅ **เก็บ API key ใน secrets manager / env** — `.gitignore` กันไฟล์ `.env`, `*.key`, `*.pem`,
  `*.log` ไว้แล้ว อย่า commit credential เด็ดขาด
- ✅ **ทุก action ต้องมี rollback + audit log** — playbook template บังคับให้ใส่

---

## 9. FAQ / แก้ปัญหาที่พบบ่อย

**Q: พิมพ์งานแล้ว skill ไม่เด้งขึ้นมา?**
A: (1) เปิด session ใหม่หลังติดตั้ง (2) ลองใช้คำ trigger ให้ชัดขึ้น เช่นระบุ "detection rule",
"IR report", "playbook" (3) เช็กว่าโฟลเดอร์อยู่ใน `~/.claude/skills/` และมีไฟล์ `SKILL.md`

**Q: script ฟ้อง `ModuleNotFoundError`?**
A: ไม่ควรเกิด เพราะทุก script ใช้ stdlib ล้วน — ตรวจว่าใช้ `python3` (ไม่ใช่ `python` เก่า)

**Q: `enrich_ioc.py` ขึ้น "no API keys set"?**
A: ปกติ — ยังไม่ได้ตั้ง env var ตั้ง `VT_API_KEY` ฯลฯ ก่อน แล้วรันใหม่

**Q: `respond_block.py` ขึ้น "REFUSED: ... never-block allowlist"?**
A: ถูกต้องแล้ว — IP นั้นอยู่ในช่วงที่ห้ามบล็อก (RFC1918 หรือที่คุณกำหนดใน `NEVER_BLOCK`)

**Q: sigma_to_queries.py แปลงแล้ว field ไม่ตรงกับ SIEM ของเรา?**
A: เป็น first-pass ต้อง map field เองตาม `resources/log-source-mapping.md`
สำหรับ production แนะนำใช้ `sigma-cli`/pySigma ที่มี backend + field-mapping pipeline

---

*License: MIT — ดู [LICENSE](LICENSE) · Issues/PR ยินดีรับครับ*
