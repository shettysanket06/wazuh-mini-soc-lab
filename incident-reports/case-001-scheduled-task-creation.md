# Case 001 — Scheduled Task Creation

**Case ID:** SOC-WAZUH-001  
**Date:** 4 November 2026  
**Endpoint:** `LAB-WIN11`  
**Wazuh agent:** `LAB-WIN11-AGENT` (ID `001`)  
**Disposition:** Benign — authorized lab activity  
**MITRE ATT&CK:** T1053 — Scheduled Task/Job

## Executive summary

Wazuh generated alert **60228** (Level 4) after Windows Security Event **4698** recorded creation of `\SOC-Lab-Persistence-Test` at 10:32:15 IST. The task was deliberately created for a controlled lab test. It had an at-startup trigger and a harmless action, `cmd.exe /c exit 0`.

Sysmon process telemetry linked the `schtasks.exe` creation command to an interactive PowerShell process and its parent process chain. The binary had a valid Microsoft Authenticode signature, and its current SHA-256 matched the value recorded by Sysmon.

The task was deleted, and a subsequent query confirmed that it no longer existed. The evidence supports a benign lab disposition; this event is not evidence of compromise.

## Detection details

| Field | Value |
|---|---|
| Wazuh rule | 60228 — A scheduled task was created |
| Wazuh level | 4 |
| Windows event | Security 4698 |
| Event record ID | 6954289 |
| Time | 10:32:15 IST (05:02:15 UTC) |
| Endpoint | `LAB-WIN11` |
| Agent | `LAB-WIN11-AGENT` |
| Creating account | `LAB-WIN11\lab-user` |
| Task | `\SOC-Lab-Persistence-Test` |

## Task configuration

| Property | Value |
|---|---|
| Trigger | Boot/startup |
| Trigger enabled | Yes |
| Hidden | No |
| Action | `cmd.exe /c exit 0` |
| Principal | `LAB-WIN11\lab-user` |
| Logon type | InteractiveToken |
| Run level | LeastPrivilege |

The task's action exits without performing another operation. A startup trigger is persistence-relevant and appropriately warrants investigation even in this controlled test.

## Timeline

All times are IST on November 4, 2026.

| Time | Evidence |
|---|---|
| 09:03:42 | Sysmon recorded `cmd.exe` PID 15188, parent `explorer.exe` PID 13268. |
| 09:03:49 | Sysmon recorded `powershell.exe` PID 14976, launched by CMD PID 15188. |
| 10:32:15 | Sysmon recorded `schtasks.exe` PID 26840 launched by PowerShell PID 14976 with the lab task creation command. |
| 10:32:15 | Security Event 4698 recorded task creation; Wazuh rule 60228 fired. |
| 10:32:15 | Task Scheduler Operational Event 106 recorded task registration locally. |
| 10:34:42 | A later `schtasks.exe /Query` was run for verification; it was not the creation process. |
| After validation | The task was deleted and a later query confirmed it was absent. |

## Process lineage

```text
explorer.exe (PID 13268)
  └── cmd.exe (PID 15188)
       └── powershell.exe (PID 14976)
            └── schtasks.exe (PID 26840)
```

The creation command was:

```text
schtasks.exe /Create /TN SOC-Lab-Persistence-Test /SC ONSTART /TR "cmd.exe /c exit 0" /F
```

## Binary verification

- Binary: `C:\Windows\System32\schtasks.exe`
- Authenticode: Valid
- Signer: Microsoft Windows
- SHA-256: `B96AF3066F0B9DE8A460F77BAAE006C5372A266BE18C561DAA7C7AE8635D399D`
- Result: Live file hash exactly matched Sysmon's event hash.

## Telemetry notes

Initially, the relevant audit sources were disabled. The lab enabled Success auditing for Other Object Access Events and enabled the Task Scheduler Operational channel, then recreated the test task. Windows recorded both Event 4698 and Event 106.

Wazuh-side receipt and alerting were confirmed for Event 4698 / rule 60228. Event 106 was confirmed locally only; its forwarding to Wazuh was not established. Both sources were left enabled for subsequent lab testing.

## Analyst assessment

Scheduled tasks with startup triggers can be abused for persistence, so Event 4698 deserves investigation. Evidence supporting the benign disposition:

1. The task was intentionally created during the lab.
2. Its name was the explicit lab marker.
3. Its action was a harmless no-op.
4. It was not hidden and used least privilege.
5. The process lineage and account matched the interactive lab session.
6. The executable signature and hash were verified.
7. The task was deleted and its absence verified.

Event 4698 establishes task creation; it does not establish that the task executed. No reboot-based execution test was performed because the task was removed after validation.

## Response and conclusion

The task was deleted and queried to verify removal. No isolation, credential reset, or malware remediation was warranted.

**Final disposition: Closed — benign authorized lab activity.**

The case demonstrates scheduled-task creation detection, correlation of Security and Sysmon telemetry, process lineage reconstruction, binary verification, and evidence-based disposition.
