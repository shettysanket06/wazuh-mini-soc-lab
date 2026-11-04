# Detection Rules

This folder contains the project-specific Wazuh rule snippet reviewed from the lab's live `local_rules.xml`.

## Contents

- `project-local-rules.xml`: custom rules 100100–100103 and the Sysmon Event ID 1 parent-rule tuning override.

## Important deployment notes

This is a **mergeable excerpt**, not a replacement for an existing `local_rules.xml`. Back up the manager's existing file and merge the required groups while preserving unrelated local rules.

Rule 100103 is a narrow validation rule for one known lab marker. It is not a general PowerShell threat detector.

The override of rule 61603 sets `noalert="1"` for Sysmon Event ID 1. This suppresses the generic parent alert and changes alert visibility. Review this trade-off carefully before reuse and validate all required alerts in a separate test environment.

After merging, validate the XML/rules and confirm the Manager starts successfully. Keep a rollback copy. Never publish full Manager/Agent configuration files or credentials.
