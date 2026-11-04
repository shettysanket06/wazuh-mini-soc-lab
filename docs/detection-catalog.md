# Detection Catalog

| Rule ID | Detection | Source | MITRE ATT&CK | Validation |
|---:|---|---|---|---|
| 100100 | `whoami.exe` execution | Sysmon Event ID 1 | T1033 — System Owner/User Discovery | Custom alert observed |
| 100101 | `ipconfig.exe` execution | Sysmon Event ID 1 | T1016 — System Network Configuration Discovery | Custom alert observed |
| 100102 | `systeminfo.exe` execution | Sysmon Event ID 1 | T1082 — System Information Discovery | Custom alert observed |
| 100103 | Marked PowerShell execution | Sysmon Event ID 1 | T1059.001 — PowerShell | Custom alert observed |
| 92027 | PowerShell spawning PowerShell | Sysmon Event ID 1 | T1059.001 — PowerShell | Built-in alert observed |
| 60228 | Scheduled task created | Security Event 4698 | T1053 — Scheduled Task/Job | Built-in alert observed |
| 60122 | Failed logon | Security Event 4625 | Wazuh mapped T1531; mapping is misleading for this event | Built-in alert observed; mapping reviewed |

## Analyst notes

- Rule levels are Wazuh alert levels, not incident severity determinations.
- Rules 100100–100102 match selected executable names. They provide activity visibility and require contextual triage; they do not prove maliciousness.
- Rule 100103 matches one dated test marker and should not be represented as general PowerShell threat detection.
- Rule 92027 identified nested PowerShell execution. The lab event was deliberately generated and benign.
- Rule 60228 detected task creation. Event 4698 proves creation, not execution.
- Rule 60122 detected an ordinary failed password attempt (4625 / substatus 0xC000006A). The observed T1531 mapping does not describe account access removal. The case report records this as a detection-content quality issue.

Detection mappings describe observed techniques; they do not establish attacker intent.
