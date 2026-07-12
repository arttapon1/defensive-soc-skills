# Example — SIEM Detection Engineer

**Prompt:** "From this brute-force-then-successful-login incident, write a detection
rule for Splunk and Sentinel."

**What the skill does:**
1. States the hypothesis: *detect T1110 by observing repeated 4625 then a 4624 from
   the same source in a short window.*
2. Authors a Sigma rule from `templates/sigma-rule-template.yml`.
3. Converts it:
   ```bash
   python3 scripts/sigma_to_queries.py --platform all rule.yml
   ```
   → first-pass SPL + KQL + EQL.
4. Aligns field names using `resources/log-source-mapping.md`, sets severity and
   expected false-positive rate, and adds positive/negative test events.

**Output:** a rule package — canonical Sigma + per-platform queries + ATT&CK mapping
+ tuning guidance + test cases, ready to review and deploy.
