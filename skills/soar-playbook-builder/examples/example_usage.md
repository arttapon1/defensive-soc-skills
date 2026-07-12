# Example — SOAR Playbook Builder

**Prompt:** "ทำ playbook: พอ SIEM เจอ IP ต้องสงสัย ให้ไปเช็ค VirusTotal ก่อน ถ้า
malicious ให้บล็อกที่ Cloudflare อัตโนมัติ แต่ต้องมี approval สำหรับ production"

**What the skill does:**
1. Defines the trigger (SIEM detection → indicator = IP).
2. Enrichment stage using `enrich_ioc.py`:
   ```bash
   python3 scripts/enrich_ioc.py 203.0.113.10
   ```
   → aggregate verdict + confidence from VT / AbuseIPDB / OTX / Group-IB.
3. Writes explicit decision logic (malicious+high-confidence → contain; suspicious →
   escalate; else close).
4. Binds the block action to Cloudflare via `respond_block.py` (dry-run first):
   ```bash
   python3 scripts/respond_block.py --integration cloudflare --action block \
       --indicator 203.0.113.10 --ttl 24h        # add --commit to apply
   ```
5. Fills `templates/playbook-template.yml` with guardrails: never-block allowlist,
   approval gate for production, TTL/expiry, rollback, audit logging.

**Output:** a vendor-neutral playbook + decision table + integration bindings + a
dry-run walkthrough showing exactly which API calls would fire.
