# Integration Catalog

Reference for binding playbook `integration:` names to real APIs. Fill in your
tenant's endpoints and store credentials in a secrets manager — **never hardcode
keys in playbooks or scripts.** All auth values below are read from environment
variables by the reference scripts.

## Threat intelligence (enrichment)

| Name | API | Auth (env var) | Key endpoint | Rate limit (free) |
|---|---|---|---|---|
| `virustotal` | VirusTotal v3 | `VT_API_KEY` | `GET /api/v3/ip_addresses/{ip}`, `/files/{hash}`, `/domains/{d}` | 4 req/min |
| `abuseipdb` | AbuseIPDB v2 | `ABUSEIPDB_API_KEY` | `GET /api/v2/check?ipAddress=` | 1000/day |
| `otx` | AlienVault OTX | `OTX_API_KEY` | `GET /api/v1/indicators/IPv4/{ip}/general` | generous |
| `groupib` | Group-IB TI (licensed) | `GROUPIB_API_KEY` / user | vendor portal endpoints | per contract |
| `shodan` | Shodan | `SHODAN_API_KEY` | `GET /shodan/host/{ip}` | per plan |

## Response / containment (device APIs)

| Name | Vendor | Auth (env var) | Block action | Notes |
|---|---|---|---|---|
| `firewall_paloalto` | Palo Alto PAN-OS | `PANOS_API_KEY`, `PANOS_HOST` | add to Dynamic Address Group / EDL | commit required; prefer DAG for no-commit |
| `firewall_fortinet` | FortiGate | `FORTI_API_TOKEN`, `FORTI_HOST` | add address + policy / threat feed | REST API |
| `firewall_checkpoint` | Check Point | `CP_SID`, `CP_HOST` | add to group + install policy | session-based auth |
| `waf_cloudflare` | Cloudflare | `CF_API_TOKEN`, `CF_ZONE` | firewall rule / IP access rule | fast, global |
| `waf_awswaf` | AWS WAF | AWS creds (role) | update IPSet | via boto3 |
| `waf_f5` | F5 BIG-IP | `F5_TOKEN`, `F5_HOST` | data-group / iRule | iControl REST |
| `ips` | (e.g. Snort/Suricata mgr) | mgr token | push block rule | reload sensor |
| `dlp` | (vendor) | vendor token | add policy / quarantine | |
| `edr` | CrowdStrike / Defender / SentinelOne | vendor token | isolate host / block hash | |
| `ticketing` | ServiceNow / Jira | `SNOW_*` / `JIRA_*` | create incident | |
| `chatops` | Slack / Teams | `SLACK_WEBHOOK` | post message | |

## Credential handling rules
- Store secrets in AWS Secrets Manager / HashiCorp Vault / Doppler / env — not in git.
- Use least-privilege API tokens scoped to the exact action (e.g. a token that can
  only modify one address group).
- Rotate tokens on a schedule; alert on use from unexpected sources.
- The reference scripts read every credential from environment variables and refuse
  to run destructive actions unless `--commit` is explicitly passed.
