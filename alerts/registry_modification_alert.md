# Registry Modification Alert

## Objective

Detect Windows Registry creation and modification events using Sysmon Event IDs 12 and 13. Registry changes are commonly associated with attacker activities such as persistence, configuration changes, and defense evasion. This alert enables SOC analysts to identify suspicious registry modifications for further investigation.

---

## Data Source

- Windows 10
- Sysmon
- Event ID 12 (Registry Object Create/Delete)
- Event ID 13 (Registry Value Set)

---

## SPL Query

```spl
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventID=12 OR EventID=13)
| table _time EventID Image TargetObject User
| sort - _time
```

---

## Alert Configuration

| Setting | Value |
|---------|-------|
| Alert Type | Scheduled |
| Schedule | Every 5 minutes (`*/5 * * * *`) |
| Time Range | Last 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Trigger | Once |
| Severity | High |
| Permissions | Private |

---

## Investigation Steps

1. Identify the process that modified the registry.
2. Review the registry key (`TargetObject`) that was created or modified.
3. Determine whether the registry location is associated with persistence (e.g., Run keys).
4. Verify whether the process is trusted or signed.
5. Correlate with recent process creation events (Sysmon Event ID 1).
6. Check for related network activity or DNS queries.
7. Determine whether the modification was authorized or potentially malicious.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Defense Evasion | Modify Registry | T1112 |

> **Note:** If the registry modification targets an autorun location (such as `Run` or `RunOnce` keys), it can also be mapped to **Persistence – T1547.001 (Registry Run Keys / Startup Folder)**.

---

## Why this Alert Matters

Attackers frequently modify the Windows Registry to establish persistence, disable security controls, hide malicious activity, or alter system behavior. Monitoring registry modifications helps SOC analysts detect suspicious changes early and investigate potential compromise before additional malicious actions occur.

---

## Alert Tuning

To reduce false positives:

- Monitor high-value registry locations first.
- Exclude known legitimate software updates if necessary.
- Correlate registry changes with process creation and network activity before escalating.

---

## Screenshot

### Alert Configuration

![Registry Modification Alert](../screenshots/alerts/registry_modification_alert.png)

### Triggered Alert

![Triggered Registry Alert](../screenshots/alerts/registry_modification_triggered.png)