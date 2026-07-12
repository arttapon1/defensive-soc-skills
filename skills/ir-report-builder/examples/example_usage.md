# Example — IR Report Builder

**Prompt:** "นี่คือ log จาก firewall กับ auth server ช่วงที่โดนโจมตี ช่วยวิเคราะห์แล้วทำรายงาน IR + สรุปผู้บริหารให้หน่อย"

**What the skill does:**
1. Runs `log_timeline.py` over the provided files:
   ```bash
   python3 scripts/log_timeline.py --tz +07:00 --out timeline.csv fw.log auth.json
   ```
   → normalized, time-ordered timeline + SHA-256 of each source file.
2. Reconstructs the attack: initial access → lateral movement → impact, each mapped
   to MITRE ATT&CK.
3. Extracts IOCs and assesses blast radius.
4. Fills `templates/ir-report-template.md` (technical) and
   `templates/exec-summary-template.md` (one-page, bilingual, impact-first).

**Output:** a detailed IR report with cited evidence + a leadership summary that
answers: what happened, impact, containment status, and what's needed from leadership.
