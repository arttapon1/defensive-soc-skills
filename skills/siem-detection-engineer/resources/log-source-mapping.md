# Log Source & Field Mapping Reference

The #1 reason a correct Sigma rule produces zero alerts is a **field/schema mismatch**
between the rule and how logs actually land in the SIEM. Fill this table for each
environment before shipping rules.

## Field mapping worksheet

| Concept | Sigma field | Splunk (CIM) | Sentinel/Defender (KQL) | Elastic (ECS) | QRadar | Wazuh |
|---|---|---|---|---|---|---|
| Source IP | `src_ip` | `src` | `SourceIP` / `RemoteIP` | `source.ip` | `sourceip` | `data.srcip` |
| Dest IP | `dst_ip` | `dest` | `DestinationIP` | `destination.ip` | `destinationip` | `data.dstip` |
| Username | `user` | `user` | `AccountName` / `UserPrincipalName` | `user.name` | `username` | `data.dstuser` |
| Host | `host` | `host` | `DeviceName` / `Computer` | `host.name` | `hostname` | `agent.name` |
| Process | `Image` | `process` | `ProcessName` / `FileName` | `process.name` | `process` | `data.win.eventdata.image` |
| Cmdline | `CommandLine` | `process` | `ProcessCommandLine` | `process.command_line` | — | `data.win.eventdata.commandLine` |
| Event ID | `EventID` | `EventCode` | `EventID` | `event.code` | `qid` | `data.win.system.eventID` |
| Timestamp | (rule `timeframe`) | `_time` | `TimeGenerated` | `@timestamp` | `starttime` | `timestamp` |

## Common log sources & where the signal lives

| Attack behavior | Best log source | Key fields |
|---|---|---|
| SSH brute force | Linux auth / `sshd` | src_ip, user, result |
| Windows credential access | Security 4625/4624/4672 | AccountName, LogonType, IpAddress |
| Web injection (SQLi/XSS) | Web/WAF access log | uri_query, status, user_agent |
| Suspicious process | EDR / Sysmon 1 | Image, CommandLine, ParentImage |
| Lateral movement | Security 4648/4624 T3, network | AccountName, LogonType, dst_ip |
| Cloud priv-esc | AWS CloudTrail / Azure Activity | eventName, userIdentity, sourceIP |
| Data staging/exfil | Proxy, DLP, netflow | bytes_out, dst_ip, category |
| C2 beaconing | DNS, proxy, netflow | dst_domain, interval, bytes |

## Coverage checklist before deploying a rule
- [ ] Log source is actually ingested and parsed (not just "on the box").
- [ ] Field names in the rule match the SIEM's normalized schema (table above).
- [ ] Timestamps are timezone-correct and not delayed enough to break `timeframe`.
- [ ] A known-good baseline exists to estimate false positives.
- [ ] Positive and negative test events verified.
