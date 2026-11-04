# Lab Build and Validation Notes

## Tested components

- Ubuntu Server 24.04.5 LTS on Oracle VirtualBox.
- Wazuh Manager 4.14.9, all-in-one installation.
- Wazuh Indexer 2.19.6.
- Windows 11 Home Single Language endpoint.
- Wazuh Windows agent 4.14.9.
- Sysmon and Windows Event Channel collection.

These are recorded lab versions from November 2026, not current-version recommendations. For a new deployment, consult the vendor's current compatibility matrix and installation guide.

## Deployment overview

1. Create an Ubuntu Server VM with virtualization enabled and sufficient memory, CPU, and disk.
2. Configure NAT for outbound access and a trusted bridged or host-only interface for endpoint connectivity. Do not expose Wazuh management ports directly to the public Internet.
3. Install the Wazuh all-in-one stack using the official guide for the chosen version.
4. Verify that Manager, Indexer, Filebeat, and Dashboard services are running.
5. Install and enroll the Windows agent using the approved registration process.
6. Configure the Windows agent to collect required Event Channels.
7. Confirm that the endpoint is Active and controlled test events arrive at the Manager.
8. Add local detections and validate them with harmless commands.

Do not publish passwords, enrollment keys, private keys, installation archives, or full Manager/Agent configuration files. Use minimal sanitized snippets only.

## Windows telemetry used

- Application
- Security
- System
- `Microsoft-Windows-Sysmon/Operational`
- `Microsoft-Windows-PowerShell/Operational`

The tested configuration used future-only collection for added channels to avoid replaying large historical event volumes after restart.

## Validation performed

### Endpoint and connectivity

- Windows agent enrolled and displayed as Active.
- Manager, Indexer, Filebeat, and Dashboard services were checked as active.
- Controlled Sysmon and PowerShell marker events were generated and observed at the Manager.

### Detection tests

- `whoami.exe` — custom rule 100100.
- `ipconfig.exe` — custom rule 100101.
- `systeminfo.exe` — custom rule 100102.
- Controlled PowerShell marker — custom rule 100103.
- Nested PowerShell execution — built-in rule 92027.
- Scheduled-task creation — Security Event 4698 / built-in rule 60228.
- Controlled failed logon — Security Event 4625 / built-in rule 60122.

### FIM

A dedicated test directory was added to real-time FIM monitoring. File creation, modification, and deletion generated alerts. A post-restart create/delete test confirmed that FIM collection remained active.

### SCA

The Windows 11 CIS benchmark assessment reported 482 checks. Four password-policy controls were remediated and rescanned. Benchmark applicability to Windows 11 Home Single Language is a material limitation; the result is not a full CIS compliance claim.

### Vulnerability Detection

The recorded snapshot showed 78 findings: 0 Critical, 27 High, 41 Medium, and 10 Low. Wireshark and VirtualBox findings were reviewed. Investigated updates were documented as recommendations and were not installed during this test.

## Safe reproduction

- Test only on systems you own or are authorized to administer.
- Use harmless commands and disposable lab artifacts.
- Do not perform destructive persistence, credential theft, malware execution, or unauthorized network scanning.
- Restore temporary settings and remove test accounts/tasks/files after validation.
- Preserve evidence without publishing raw sensitive logs.

## Project-specific rules

See [the reviewed local-rule excerpt](../detections/project-local-rules.xml). It contains rules 100100–100103 and the lab's overwrite of built-in rule 61603. The unrelated stock Wazuh SSH example rule 100001 was omitted.

**Do not replace an existing `local_rules.xml` with this snippet.** Back up the live file and merge the relevant groups while preserving unrelated rules. The 61603 override has `noalert="1"`, suppressing its generic parent alert for Sysmon Event ID 1; validate the alert-visibility trade-off in a separate environment. Rule 100103 is a one-marker validation rule, not a general PowerShell detector.

After merging, validate before restarting:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Proceed only if the syntax test succeeds and the Manager reports active. Keep a rollback copy and re-test harmless endpoint events.
