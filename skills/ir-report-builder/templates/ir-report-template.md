# Incident Response Report / รายงานการตอบสนองต่อเหตุการณ์

**Incident ID:** IR-YYYY-NNNN  ·  **Severity:** ____  ·  **Status:** ____
**Reporting window:** ____ (TZ: ____)  ·  **Author:** ____  ·  **Distribution:** [TLP:AMBER]

---

## 1. Executive Summary
_See exec-summary-template.md — 1 page, business-first._

## 2. Incident Overview
- Incident type: ____
- Detection source & time: ____
- Affected assets / accounts: ____
- Business criticality: ____

## 3. Evidence Sources & Integrity
| Source | Format | Time range | File hash (SHA-256) | Notes |
|---|---|---|---|---|
| ____ | ____ | ____ | ____ | ____ |

> Chain of custody: all analysis performed on read-only copies. Original hashes recorded above.

## 4. Attack Timeline
| Timestamp (UTC) | Source | Event | ATT&CK | Phase |
|---|---|---|---|---|
| ____ | ____ | ____ | Txxxx | Initial Access |
| ____ | ____ | ____ | Txxxx | Execution |
| ____ | ____ | ____ | Txxxx | Lateral Movement |
| ____ | ____ | ____ | Txxxx | Impact |

Key milestones:
- **Initial access:** ____
- **First malicious action:** ____
- **Detection lag (dwell time):** ____
- **Last observed activity:** ____

## 5. Root Cause Analysis
- Exploited weakness: ____
- Why existing controls did not stop it: ____
- Contributing factors: ____

## 6. Impact Assessment
- Data accessed / exfiltrated: ____
- Systems compromised: ____
- Integrity / availability effects: ____
- Confidence: [High / Medium / Low]

## 7. MITRE ATT&CK Mapping
| Tactic | Technique (ID) | Evidence ref |
|---|---|---|
| ____ | ____ | ____ |

## 8. Indicators of Compromise (IOCs)
| Type | Value | Context | First seen | Confidence |
|---|---|---|---|---|
| IP | ____ | ____ | ____ | ____ |
| Domain | ____ | ____ | ____ | ____ |
| Hash | ____ | ____ | ____ | ____ |
| Account | ____ | ____ | ____ | ____ |

## 9. Response Actions (PICERL)
### Containment
| Action | Status (done/recommended) | Owner | Priority |
|---|---|---|---|
| ____ | ____ | ____ | ____ |

### Eradication
| Action | Status | Owner | Priority |
|---|---|---|---|

### Recovery
| Action | Status | Owner | Priority |
|---|---|---|---|

## 10. Lessons Learned & Recommendations
- Detection gaps → hand off to `siem-detection-engineer`: ____
- Response steps to automate → hand off to `soar-playbook-builder`: ____
- Control improvements: ____

## Appendix A — Raw Evidence Excerpts
```
<paste cited log lines with timestamps>
```

## Appendix B — Visibility / Logging Gaps
- ____
