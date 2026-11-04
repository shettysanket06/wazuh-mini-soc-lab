# Case 002 — Windows Authentication Failure Investigation

**Status:** Closed  
**Disposition:** Benign — authorized controlled lab activity  
**Endpoint:** `LAB-WIN11`  
**Wazuh agent:** `LAB-WIN11-AGENT` (ID `001`)  
**Relevant event date:** 3 November 2026

## Executive summary

Windows Security Event **4625** recorded one failed interactive logon for a temporary local account, `LAB-WIN11\SOC-Lab-Test`, at 17:48:58 IST. Wazuh generated rule **60122**, Level 5. The event recorded status `0xC000006D` and substatus `0xC000006A` (incorrect password), logon type 2, and source `::1` (IPv6 loopback).

Account lifecycle events showed the temporary account being created, enabled/configured, used in one controlled failed authentication attempt, and deleted. Sysmon identified the Windows Secondary Logon service (`seclogon`) hosted by `svchost.exe` as the authentication handler. Its signature was valid and its hash matched the Sysmon event.

The activity matches the controlled lab test. The reviewed evidence does not establish brute force, remote access, or account compromise.

## Detection details

| Attribute | Evidence |
|---|---|
| Wazuh rule | 60122 |
| Wazuh level | 5 |
| Windows event | Security 4625 |
| Event time | 17:48:58 IST (12:18:59 UTC) |
| Target | `LAB-WIN11\SOC-Lab-Test` |
| Initiator | `LAB-WIN11\lab-user` |
| Logon type | 2 — Interactive |
| Status / substatus | `0xC000006D` / `0xC000006A` |
| Workstation / source | `LAB-WIN11` / `::1` |
| Logon process | `seclogo` |
| Authentication package | Negotiate |
| Caller | `C:\Windows\System32\svchost.exe`, PID 24788 |

## Account lifecycle

| Time (IST, Nov 3) | Event ID | Finding |
|---|---:|---|
| 17:47:20 | 4720 | Temporary account created. Initial UAC 0x15; account disabled and Password Not Required enabled. |
| 17:47:20 | 4722 | Account enabled. |
| 17:47:20 | 4738 | Account changed; UAC 0x15 to 0x10. Account enabled, Password Not Required disabled, Password Last Set reported as 17:47:20. |
| 17:47:20 | 4724 | Event states an attempt was made to reset the account password. The formatted output did not expose its success/failure keyword. |
| 17:48:58 | 4625 | One failed interactive logon; bad-password substatus. |
| 17:54:42 | 4726 | Temporary account deleted. |

The account-management events share the same displayed second; their finer ordering cannot be established from the supplied event renderings.

## Authentication process investigation

Sysmon Event ID 1 identified:

- Image: `C:\Windows\System32\svchost.exe`
- PID: 24788 (hex `0x60d4`)
- Command line: `svchost.exe -k netsvcs -p -s seclogon`
- Service: Secondary Logon (`seclogon`)
- User: `NT AUTHORITY\SYSTEM`
- Parent: `services.exe`, PID 1368
- SHA-256: `1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2`

The service group and `-s seclogon` argument are consistent with Windows Secondary Logon handling an alternate-credential request.

### Binary verification

- Authenticode status: Valid
- Signer: Microsoft Windows
- Current SHA-256: `1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2`
- Result: Current file hash exactly matched Sysmon's process-creation hash.

## MITRE mapping quality finding

Wazuh rule 60122 mapped the failed-logon alert to **T1531 — Account Access Removal**. The observed Event 4625 documents a failed logon, not removal of account access. The temporary account was deleted later as part of lab cleanup (Event 4726), but that separate action does not make T1531 an accurate mapping for the failed-logon alert.

This is a detection-content quality issue. The mapping should not be repeated as the analyst conclusion.

## Assessment and limitations

**Disposition: Benign — authorized lab activity.**

Supporting evidence:

1. The target was a deliberately created temporary lab account.
2. Its creation, enablement/configuration, failed logon, and deletion were correlated by account identity.
3. The attempt was local (loopback) and interactive, not a remote network logon.
4. The Secondary Logon service context was identified.
5. The `svchost.exe` signature and hash were verified.
6. One matching Event 4625 was present in the reviewed account-specific time window.

The review covers the retained events and stated time window; it does not prove that no other authentication activity occurred outside that scope. The 4724 rendering did not expose its success/failure keyword, so password-reset success is not asserted solely from that event.

## Response and closure

The temporary account was deleted (Event 4726). No further remediation was required. The misleading T1531 mapping was recorded for detection-quality review.

**Final disposition: Closed — benign authorized lab activity.**
