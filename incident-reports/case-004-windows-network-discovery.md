# Case 004 — Windows Network Discovery Investigation

**Disposition:** Benign — authorized lab activity  
**Endpoint:** `LAB-WIN11` / agent `LAB-WIN11-AGENT`  
**Date:** 4 November 2026  
**Wazuh alert:** Rule 100101, Level 3  
**MITRE ATT&CK:** T1016 — System Network Configuration Discovery

## Executive summary

Custom Wazuh rule 100101 detected `ipconfig.exe /all` on the Windows endpoint. The process ran as the lab user and was launched by the interactive PowerShell process with PID 14976.

The executable's Authenticode signature was valid and its current SHA-256 exactly matched the hash recorded by Sysmon. The command is a legitimate Windows utility for displaying local network configuration. Although network discovery can be used during reconnaissance, this event alone does not demonstrate malicious activity, active scanning, lateral movement, or exfiltration.

## Detection evidence

| Attribute | Value |
|---|---|
| Rule ID | 100101 |
| Rule description | Windows discovery command executed: ipconfig.exe |
| Wazuh level | 3 |
| Telemetry | Sysmon Event ID 1 |
| Event record | 26764 |
| Time | 09:58:46 IST (04:28:46 UTC) |
| Endpoint / agent | `LAB-WIN11` / `LAB-WIN11-AGENT` |
| Process image | `C:\Windows\System32\ipconfig.exe` |
| Command line | `ipconfig.exe /all` |
| PID | 20508 |
| User | `LAB-WIN11\lab-user` |
| Integrity | High |
| Parent | PowerShell PID 14976 |
| Process SHA-256 | `97E67E94E477DF42CC18C6C1E489DF120693364B62961F05E8BE049D6917D387` |

## Process relationship

```text
explorer.exe (PID 13268)
  └── cmd.exe (PID 15188)
       └── powershell.exe (PID 14976)
            └── ipconfig.exe (PID 20508)
                 Command: ipconfig.exe /all
```

The Case 004 event directly proves the PowerShell-to-ipconfig relationship. Earlier Sysmon records support the Explorer-to-CMD-to-PowerShell ancestry.

## Binary verification

- File: `C:\Windows\System32\ipconfig.exe`
- Authenticode: Valid
- Signer: Microsoft Windows
- SHA-256: `97E67E94E477DF42CC18C6C1E489DF120693364B62961F05E8BE049D6917D387`
- Result: Live file hash exactly matched the Sysmon event hash.

## Analyst assessment

The command enumerates local network configuration, including adapter and IP settings. Wazuh appropriately mapped the activity to T1016.

Evidence supporting a benign disposition:

1. The command was part of the controlled lab test.
2. The command line was the standard `ipconfig.exe /all` invocation.
3. The process ran under the expected interactive user.
4. Its parent was the known lab PowerShell process.
5. The executable had a valid Microsoft signature and matching hash.

The event does not prove active network scanning, contact with other hosts, lateral movement, or data transmission.

## Response and conclusion

No containment, quarantine, or remediation was required. The custom detection was retained as useful visibility into network discovery activity.

**Final disposition: Closed — benign authorized lab activity.**
