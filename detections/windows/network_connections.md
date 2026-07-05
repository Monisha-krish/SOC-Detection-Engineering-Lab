# Network Connection Detection

## Objective

Detect outbound network connections initiated by Windows processes using Sysmon Event ID 3. This detection helps identify suspicious communication with external systems, command-and-control (C2) servers, malware callbacks, or unauthorized network activity.

---

## Data Source

* Windows 10
* Sysmon
* Event ID 3 (Network Connection)

---

## Detection Logic

Monitor all outbound network connections and correlate them with the originating process.

---

## SPL Query

```spl
index=main EventID=3
| table _time Computer User Image DestinationIp DestinationHostname DestinationPort Protocol
```

---

## Sample Output

| Time                | Process        | Destination IP  | Port |
| ------------------- | -------------- | --------------- | ---- |
| 2026-07-04 08:47:20 | PowerShell.exe | 142.xxx.xxx.xxx | 443  |

---

## Investigation Steps

1. Identify the originating process.
2. Verify whether the destination IP is trusted.
3. Check the destination hostname.
4. Review the destination port.
5. Correlate with PowerShell execution (Event ID 1).
6. Correlate with DNS queries (Event ID 22).

---

## MITRE ATT&CK

| Technique                                     | ID        |
| --------------------------------------------- | --------- |
| Application Layer Protocol                    | T1071     |
| Command and Scripting Interpreter: PowerShell | T1059.001 |

---

## Why this Detection Matters

Attackers frequently establish outbound connections to command-and-control infrastructure after executing malicious code. Monitoring network connections helps SOC analysts detect suspicious communications, investigate compromised hosts, and identify malware activity.

---

## Screenshot

![Network Connection Detection](../../screenshots/windows/network_connections.png)