# Case 003 — Windows PowerShell Process Execution Investigation

**Disposition:** Benign — authorized lab activity  
**Endpoint:** `LAB-WIN11` / agent `LAB-WIN11-AGENT`  
**Date:** 4 November 2026  
**Wazuh alert:** Rule 92027, Level 4  
**MITRE ATT&CK:** T1059.001 — PowerShell

## Executive summary

Wazuh generated a Level 4 alert when a PowerShell process spawned another PowerShell process. The child executed a deliberate lab command using the marker `SOC_LAB_POWERSHELL_TEST_20261104` and `Write-Output`.

The investigation reviewed Sysmon process-creation telemetry, correlated the parent-child relationship, and verified the PowerShell executable's Authenticode signature and SHA-256. The evidence supports the authorized lab context; this event is not evidence of compromise.

## Detection evidence

| Attribute | Value |
|---|---|
| Rule ID | 92027 |
| Rule description | Powershell process spawned powershell instance |
| Wazuh level | 4 |
| Alert ID | `1793766657.878835` |
| Wazuh timestamp | 04:30:57.731 UTC / 10:00:57.731 IST |
| Telemetry | Sysmon Event ID 1 |
| Event record | 26803 |
| Endpoint / agent | `LAB-WIN11` / `LAB-WIN11-AGENT` |
| User | `LAB-WIN11\lab-user` |

## Child process

- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- PID: 25940
- Command: `powershell.exe -NoProfile -Command "Write-Output 'SOC_LAB_POWERSHELL_TEST_20261104'"`
- Process SHA-256: `D8F182560210D43BAAF767D482AD1DC1207372522E91413B9D5E515A875E552D`

## Process lineage

```text
explorer.exe (PID 13268)
  └── cmd.exe (PID 15188)
       └── powershell.exe (PID 14976)
            └── powershell.exe (PID 25940)
```

The alert directly records PowerShell PID 14976 as the child process's parent. Earlier Sysmon records linked PID 14976 to CMD PID 15188 and CMD PID 15188 to Explorer PID 13268. This chain is consistent with the interactive lab session.

## Executable verification

| Check | Result |
|---|---|
| Authenticode | Valid |
| Signer | Microsoft Windows |
| Current SHA-256 | `D8F182560210D43BAAF767D482AD1DC1207372522E91413B9D5E515A875E552D` |
| Match to Sysmon hash | Exact match |

## Analyst assessment

Nested PowerShell execution merits review because PowerShell can be abused. The process relationship alone does not establish malicious intent.

Evidence supporting the benign disposition:

- The command line contains the deliberately generated lab marker.
- The child used `-NoProfile` and `Write-Output`; no encoded payload or download was present in the recorded command.
- The parent-child relationship matched the interactive lab session.
- The user context was the expected lab user.
- The binary signature was valid and the hash matched Sysmon's event value.

**Conclusion:** Benign authorized lab activity. Rule 92027 correctly identified nested PowerShell execution; this was a legitimate detection of a behavior, not evidence of compromise.

## Limitations and response

This case addresses the specific alert and process chain, not all PowerShell activity on the endpoint. No containment or remediation was warranted. Retain the detection and use command-line context, user/session context, parent process, and binary reputation to prioritize future alerts.

**Final disposition: Closed — benign authorized lab activity.**
